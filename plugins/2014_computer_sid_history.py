"""
Plugin 2014: Computer Account Has SID History

Same technique as user-account plugin 1008, applied to computer objects.
Legitimate during domain/forest migrations, but also a well-documented
persistence and privilege-escalation mechanism.

[v1.3] Entries are now classified like user-account plugin 1008: a SID
from this domain itself (never legitimate migration residue), a
privileged well-known RID (-500/-502/-512/-516/-518/-519/-520/-521/-498/
-526/-527), any BUILTIN SID (S-1-5-32-*) or Enterprise Domain Controllers
(S-1-5-9) makes the finding critical and is listed in
dangerous_sid_history; foreign-domain-only residue drops from high to
medium (still critical on a DC). Previously every entry got a flat high.

[v1.4] Collector 0.5.16 stores sIDHistory as real "S-1-5-..." strings
(before, it was base64/garbled, so the classification above could never
match). Checked against real SIDs: a privileged RID now only matches a
domain SID (S-1-5-21-a-b-c-RID) and BUILTIN only S-1-5-32-RID. Values
that are not SID strings (rows from before 0.5.16, until the
--full-rescan) are listed in detail.undecoded_sid_history and never
counted as dangerous; detail also gains same_domain_sid_history. Summary
wording fixed: "entrie(s)" -> "entry"/"entries" (summaries change once).
"""

PLUGIN = {
    "plugin_id": 2014,
    "category": "Computer Accounts",
    "name": "Computer Account Has SID History",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Investigate and confirm whether this is legitimate residue from "
        "a completed domain/forest migration. If migration is fully "
        "complete and SID history is no longer needed, clear it "
        "(`Set-ADComputer -Clear SIDHistory`). If found on a computer "
        "object with no known migration history, treat it as a probable "
        "compromise indicator and escalate to incident response rather "
        "than clearing it first."
    ),
    "control_id": "PRIV-202",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1134.005",
    ],
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
        "same reasoning as user-account plugin 1008, applied here to "
        "computer objects. Rated critical when any entry is a SID from "
        "this domain itself, a privileged well-known RID (Administrator, "
        "Domain Admins, Domain Controllers, Schema/Enterprise Admins, "
        "GPCO, RODCs, Key Admins, ...), a BUILTIN SID or Enterprise "
        "Domain Controllers, or when the computer is a domain controller; "
        "medium for SIDs of other domains only (typical migration "
        "residue, still to be cleaned up; classification needs collector "
        "0.5.16+, which decodes sIDHistory to SID strings). NOT downgraded when the computer account is "
        "disabled: sIDHistory is a persistent configuration on the "
        "object itself and survives disablement untouched, reactivating "
        "immediately if the account is ever re-enabled."
    ),
    "base_severity": "high",
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
            SELECT cl.domain_sid FROM client cl
            WHERE cl.client_id = %(client_id)s AND cl.domain_sid IS NOT NULL
        ),
        entries AS (
            -- [v1.4] sIDHistory holds "S-1-5-..." strings since collector
            -- 0.5.16; earlier rows hold undecoded binary (base64/garbled).
            SELECT c.object_guid, sh,
                   sh ~ '^S-1-[0-9]+(-[0-9]+)+$' AS is_sid,
                   EXISTS (SELECT 1 FROM dom WHERE sh LIKE dom.domain_sid || '-%%') AS same_domain,
                   (sh ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(500|502|512|516|518|519|520|521|498|526|527)$'
                    OR sh ~ '^S-1-5-32-[0-9]+$'
                    OR sh = 'S-1-5-9') AS privileged_sid
            FROM ad_computer c
            CROSS JOIN LATERAL unnest(c.sid_history) AS sh
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
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
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller OR f.dangerous_sids IS NOT NULL
                 THEN 'critical' ELSE 'medium' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has SID history populated (' || array_length(c.sid_history, 1)
                || CASE WHEN array_length(c.sid_history, 1) = 1 THEN ' entry' ELSE ' entries' END
                || CASE WHEN f.dangerous_sids IS NOT NULL
                        THEN ', including a privileged or same-domain SID' ELSE '' END
                || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'sid_history', c.sid_history,
                'dangerous_sid_history', f.dangerous_sids,
                'same_domain_sid_history', f.same_domain_sids,
                'undecoded_sid_history', f.undecoded,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        LEFT JOIN flagged f ON f.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.sid_history IS NOT NULL
          AND array_length(c.sid_history, 1) > 0
    """,
}
