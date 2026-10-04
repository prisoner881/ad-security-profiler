"""
Plugin 3001: Group Has SID History

Same technique as user-account plugin 1008 and computer-account plugin
2014, applied to group objects. Legitimate during domain/forest
migrations, but also a well-documented persistence and
privilege-escalation mechanism -- and arguably more consequential on a
group than an individual account, since group membership propagates to
everyone who is (or later becomes) a member.

[v1.3] Grades severity by SID content: an entry carrying this domain's
own SID prefix (client.domain_sid -- never legitimate migration residue,
the classic injection signature) or ending in a privileged RID
(-500/-502/-512/-516/-518/-519/-526/-527/-544/-548/-549/-550/-551) is
critical regardless of adminCount; those entries are listed in
detail.suspicious_sid_history. Fixed "entrie(s)" wording.

[v1.4] Collector 0.5.16 stores sIDHistory as real "S-1-5-..." strings
(it was base64/garbled before, so nothing could be classified). The
classification now matches plugins 1008/2014 and is anchored on the SID
format: a privileged RID (-500/-502/-512/-516/-518/-519/-520/-521/-498/
-526/-527) only counts on a domain SID (S-1-5-21-a-b-c-RID) -- the old
"ends in -544/-548..." test also matched ordinary domain RIDs 544-551 --
any BUILTIN S-1-5-32-* and Enterprise Domain Controllers (S-1-5-9) are
added, and the domain SID is taken from ad_domain as well as
client.domain_sid. Non-SID values (rows from before 0.5.16, until the
--full-rescan) are listed in detail.undecoded_sid_history and never
counted as suspicious. Summary: "N same-domain or privileged-RID" now
reads "N same-domain or privileged" (it also counts BUILTIN/S-1-5-9).
"""

PLUGIN = {
    "plugin_id": 3001,
    "category": "Groups",
    "name": "Group Has SID History",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Investigate and confirm whether this is legitimate residue from "
        "a completed domain/forest migration. If migration is fully "
        "complete and SID history is no longer needed, clear it "
        "(`Set-ADGroup -Clear SIDHistory`). If found on a group with no "
        "known migration history, treat it as a probable compromise "
        "indicator and escalate to incident response rather than "
        "clearing it first -- a privileged SID injected into a group's "
        "history grants that privilege to every current and future "
        "member of the group, not just one account."
    ),
    "control_id": "PRIV-301",
    "framework_tags": ["MITRE-ATTCK-T1134.005"],
    "references": [
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation -- SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "Microsoft Defender for Identity: Unsecure SID-History attribute",
         "url": "https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-unsecure-sid-history-attribute"},
    ],
    "description": (
        "sIDHistory is legitimately populated during domain/forest "
        "migrations, but is also a well-documented persistence and "
        "privilege-escalation technique (MITRE ATT&CK T1134.005) -- the "
        "same reasoning as plugins 1008 and 2014, applied here to group "
        "objects. Arguably more consequential on a group than an "
        "individual account: a privileged SID injected into a group's "
        "history is inherited by every current and future member of "
        "that group, not just a single compromised principal. Severity is "
        "critical when the group is protected (adminCount=1) or when any "
        "SID-history entry is from this same domain, is a domain SID with "
        "a privileged RID (Administrator, krbtgt, Domain/Enterprise/Schema/"
        "Key Admins, Domain Controllers, GPCO, RODCs), any BUILTIN SID "
        "(S-1-5-32-*, e.g. Administrators and the operator groups) or "
        "Enterprise Domain Controllers (S-1-5-9); high otherwise. Requires "
        "collector 0.5.16+, which decodes sIDHistory to SID strings."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            -- [v1.4] this client's domain SID(s): ad_domain and client
            SELECT DISTINCT o.object_sid AS domain_sid
            FROM ad_domain d
            JOIN directory_object o
                ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
              AND o.object_sid IS NOT NULL
            UNION
            SELECT cl.domain_sid FROM client cl
            WHERE cl.client_id = %(client_id)s AND cl.domain_sid IS NOT NULL
        ),
        g AS (
            SELECT
                g.*,
                (SELECT array_agg(DISTINCT h ORDER BY h)
                   FROM unnest(g.sid_history) AS h
                  WHERE h ~ '^S-1-[0-9]+(-[0-9]+)+$'
                    AND (EXISTS (SELECT 1 FROM dom WHERE h LIKE dom.domain_sid || '-%%')
                         OR h ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(500|502|512|516|518|519|520|521|498|526|527)$'
                         OR h ~ '^S-1-5-32-[0-9]+$'
                         OR h = 'S-1-5-9')
                ) AS suspicious,
                (SELECT array_agg(DISTINCT h ORDER BY h)
                   FROM unnest(g.sid_history) AS h
                  WHERE h !~ '^S-1-[0-9]+(-[0-9]+)+$'
                ) AS undecoded
            FROM ad_group g
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              AND g.sid_history IS NOT NULL
              AND array_length(g.sid_history, 1) > 0
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.is_protected_group OR g.suspicious IS NOT NULL
                 THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN g.is_protected_group THEN 'Privileged ' ELSE '' END)
                || 'Group ' || COALESCE(g.sam_account_name, g.object_guid::text)
                || ' has SID history populated (' || array_length(g.sid_history, 1)
                || CASE WHEN array_length(g.sid_history, 1) = 1 THEN ' entry' ELSE ' entries' END
                || CASE WHEN g.suspicious IS NOT NULL
                        THEN ', ' || array_length(g.suspicious, 1)
                             || ' same-domain or privileged'
                        ELSE '' END
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'sid_history', g.sid_history,
                'suspicious_sid_history', g.suspicious,
                'undecoded_sid_history', g.undecoded,
                'is_protected_group', g.is_protected_group,
                'member_count_direct', g.member_count_direct
            ) AS detail
        FROM g
    """,
}
