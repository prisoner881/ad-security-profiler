"""
Plugin 1008: SID History Present on User Account

sIDHistory is legitimately used during domain/forest migrations to
preserve access during a transition, but it's also a well-known
persistence and privilege-escalation mechanism (MITRE ATT&CK T1134.005,
SID-History Injection) -- an account with SID history matching a
privileged SID can inherit that privilege without any visible group
membership showing why.

[v1.5] Severity now separates injection indicators from migration residue:
critical when any sIDHistory entry is a privileged well-known SID (domain
RIDs 500 Administrator, 502 krbtgt, 512 DA, 516 DCs, 518 Schema Admins,
519 EA, 520 GPCO, 521/498 (Enterprise) RODCs, 526/527 (Enterprise) Key
Admins; any BUILTIN S-1-5-32-*; Enterprise Domain Controllers S-1-5-9) or
carries the account's OWN domain SID prefix (never produced by a legitimate
migration); high otherwise. detail lists the flagged entries. Summary
wording fixed ("entrie(s)" -> "entry"/"entries") and gains ", including a
privileged or same-domain SID" when critical -- existing summaries change
once. Title corrected (disabled accounts are in scope by design).

[v1.6] Collector 0.5.16 stores sIDHistory as real "S-1-5-..." strings
(before, ldap3 had no formatter for it and it was stored base64/garbled,
so no entry could ever be classified and every finding stayed high).
Classification checked against real SIDs: a privileged RID now only
matches a domain SID (S-1-5-21-a-b-c-RID), BUILTIN only a well-formed
S-1-5-32-RID, and the account's own domain is taken from both ad_domain
and client.domain_sid. Values that are not SID strings (rows collected
before 0.5.16, until the --full-rescan) are listed in
detail.undecoded_sid_history and never counted as dangerous; detail also
gains same_domain_sid_history. NULL-safe summary name fallback.
"""

PLUGIN = {
    "plugin_id": 1008,
    "category": "User Accounts",
    "name": "User Account Has SID History",
    "version": "1.6",
    "revision_date": "2026-10-04",
    "remediation": (
    'Investigate and confirm whether this is legitimate residue from a '
    'completed domain/forest migration. If migration is fully complete and SID '
    'history is no longer needed for resource access, clear it (`Set-ADUser '
    '-Clear SIDHistory`, which requires elevated rights and may require a DC '
    'restart in some configurations). If found on an account with no known '
    'migration history, treat it as a probable compromise indicator and '
    'escalate to incident response immediately rather than clearing it -- '
    'clearing first may destroy evidence of how it was set.'
),
    "control_id": "PRIV-103",
    "framework_tags": ["MITRE-ATTCK-T1134.005"],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation -- SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "Microsoft Defender for Identity: Unsecure SID-History attribute",
         "url": "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute"},
    ],
    "description": (
        "sIDHistory is legitimately populated during domain/forest "
        "migrations to preserve access during a transition, but is also "
        "a well-documented persistence and privilege-escalation "
        "technique (MITRE ATT&CK T1134.005, SID-History Injection) -- an "
        "account with a privileged SID in its history can inherit that "
        "privilege without it appearing as ordinary group membership. "
        "Any finding here, especially outside a known, recent, "
        "in-progress migration, warrants direct investigation rather "
        "than being assumed benign. NOT downgraded when the account is "
        "disabled: sIDHistory is a persistent configuration on the "
        "object itself, not something that requires the account to "
        "currently be usable -- it survives disablement untouched and "
        "reactivates immediately if the account is ever re-enabled by "
        "anyone, including whoever set up the persistence in the first place. "
        "Critical when an entry is a privileged well-known SID (e.g. "
        "-500/-512/-516/-518/-519, BUILTIN S-1-5-32-*) or has the account's "
        "own domain SID prefix -- neither results from a legitimate "
        "migration; high for other (foreign-domain, unprivileged) entries. "
        "Requires collector 0.5.16+ (sIDHistory decoded to SID strings) for "
        "the critical classification; older rows are listed as undecoded."
    ),
    "base_severity": "high",
    # [v1.5] critical when an entry is a privileged well-known SID or comes
    # from this account's own domain (SID-History injection indicators, as
    # PingCastle's "dangerous SID history" rule); high for other entries.
    "query": """
        WITH dom AS (
            -- this client's domain SID(s), to spot same-domain sIDHistory
            SELECT DISTINCT o.object_sid AS domain_sid
            FROM ad_domain d
            JOIN directory_object o
                ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
              AND o.object_sid IS NOT NULL
            UNION
            -- [v1.6] also the client's recorded domain SID
            SELECT cl.domain_sid FROM client cl
            WHERE cl.client_id = %(client_id)s AND cl.domain_sid IS NOT NULL
        ),
        entries AS (
            -- [v1.6] sIDHistory holds "S-1-5-..." strings since collector
            -- 0.5.16; earlier rows hold undecoded binary (base64/garbled).
            SELECT u.object_guid, sh,
                   sh ~ '^S-1-[0-9]+(-[0-9]+)+$' AS is_sid,
                   EXISTS (SELECT 1 FROM dom WHERE sh LIKE dom.domain_sid || '-%%') AS same_domain,
                   (sh ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(500|502|512|516|518|519|520|521|498|526|527)$'
                    OR sh ~ '^S-1-5-32-[0-9]+$'
                    OR sh = 'S-1-5-9') AS privileged_sid
            FROM ad_user u
            CROSS JOIN LATERAL unnest(u.sid_history) AS sh
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND sh IS NOT NULL
        ),
        flagged AS (
            SELECT e.object_guid,
                   array_agg(DISTINCT e.sh ORDER BY e.sh)
                       FILTER (WHERE e.is_sid AND (e.same_domain OR e.privileged_sid)) AS dangerous_sids,
                   array_agg(DISTINCT e.sh ORDER BY e.sh)
                       FILTER (WHERE e.is_sid AND e.same_domain) AS same_domain_sids,
                   array_agg(DISTINCT e.sh ORDER BY e.sh)
                       FILTER (WHERE NOT e.is_sid) AS undecoded
            FROM entries e
            GROUP BY e.object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN f.dangerous_sids IS NOT NULL THEN 'critical' ELSE 'high' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text)
                || ' has SID history populated (' || array_length(u.sid_history, 1)
                || CASE WHEN array_length(u.sid_history, 1) = 1 THEN ' entry' ELSE ' entries' END
                || CASE WHEN f.dangerous_sids IS NOT NULL
                        THEN ', including a privileged or same-domain SID' ELSE '' END
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'sid_history', u.sid_history,
                'dangerous_sid_history', f.dangerous_sids,
                'same_domain_sid_history', f.same_domain_sids,
                'undecoded_sid_history', f.undecoded
            ) AS detail
        FROM ad_user u
        LEFT JOIN flagged f ON f.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.sid_history IS NOT NULL
          AND array_length(u.sid_history, 1) > 0
    """,
}
