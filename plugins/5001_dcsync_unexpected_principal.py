"""
Plugin 5001: DCSync Replication Rights Held by an Unexpected Principal

The single most classic ACL-derived AD finding, and the flagship
motivation for solving this project's long-deferred ACL-parsing
capability. DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
together grant the ability to impersonate a domain controller and pull
password hashes for any account via DCSync -- Mimikatz's
lsadump::dcsync, and the technique behind MITRE ATT&CK T1003.006.

GUIDs confirmed directly against impacket's own msada_guids reference
table (sourced from Microsoft's MS-ADA1/2/3 specs), not assumed from a
single web source -- a real, resolved discrepancy was found across
public sources during development, and impacket's embedded table
(reinforced by its own real exploitation code in
examples/ntlmrelayx/attacks/ldapattack.py, which grants exactly this
GUID pair to actually perform a working DCSync) was used as the
authoritative tiebreaker.

Excludes the well-known, expected holders: Domain Admins, Enterprise
Admins, Administrators (BUILTIN), and any domain controller computer
account -- flagging only principals outside that expected set.

A trustee SID that doesn't resolve to a collected directory_object
(e.g. a genuinely cross-forest/orphaned SID) is not flagged as an
individual finding here -- control_evidence_fact.object_guid has a hard
foreign key against directory_object, so a finding can only be attached
to a real, collected object, matching the same "count but don't
individually report unresolved references" precedent already
established throughout this project for group membership, delegation
targets, and RBCD trustees.

[v1.1] Fixed two real false positives found against production data
(forge.local): Enterprise Domain Controllers (S-1-5-9) and Enterprise
Read-only Domain Controllers (RID 498) are both confirmed, by
Microsoft's own documentation, to be DEFAULT holders of replication
rights -- not misconfigurations. Deliberately did NOT exclude the
"Domain Controllers" group (RID 516) itself, even though it also showed
up in that same real run: Microsoft's own troubleshooting documentation
explicitly and repeatedly instructs that group's replication rights be
CLEARED, not granted, and dedicated Windows Event IDs (1979-1983) exist
specifically to detect this exact condition as a default-security-
descriptor anomaly. A finding on that group is a genuine, if
lower-confidence, anomaly worth surfacing, not a default to suppress.
"""

PLUGIN = {
    "plugin_id": 5001,
    "category": "ACLs",
    "name": "DCSync Replication Rights Held by an Unexpected Principal",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Confirm this grant was deliberate and is still needed. "
        "Service accounts frequently accumulate replication rights for "
        "legitimate purposes (Azure AD Connect / Entra Connect, backup "
        "software, directory sync tools), so this is not automatically "
        "an active compromise -- but any account holding it is a "
        "high-value target: compromising it is equivalent to "
        "compromising a domain controller for credential-theft "
        "purposes. If not needed, remove the grant "
        "(`dsacls \"DC=...\" /R DS-Replication-Get-Changes` and the "
        "-All variant, or via ADSI Edit) rather than leaving standing "
        "access broader than required."
    ),
    "control_id": "ACL-001",
    "framework_tags": ["MITRE-ATTCK-T1003.006"],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-"
        "00c04fc2dcd2) and DS-Replication-Get-Changes-All "
        "(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2) together grant the "
        "ability to impersonate a domain controller and pull password "
        "hashes for any account via DCSync -- Mimikatz's "
        "lsadump::dcsync, MITRE ATT&CK T1003.006. By default only "
        "Domain Admins, Enterprise Admins, Administrators, and domain "
        "controller computer accounts hold this pair. This finding "
        "flags any OTHER principal holding either right on the domain "
        "root, since a real DCSync attack needs both but a partial "
        "grant is itself worth investigating -- it either indicates an "
        "in-progress/incomplete grant or a misconfiguration."
    ),
    "base_severity": "critical",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              -- 512=Domain Admins, 519=Enterprise Admins, 544=Administrators,
              -- 498=Enterprise Read-only Domain Controllers (confirmed
              -- against Microsoft's own MS-ADTS spec and multiple KB
              -- articles as a by-design DEFAULT holder of exactly
              -- DS-Replication-Get-Changes, deliberately NOT the -All
              -- variant -- Microsoft's own troubleshooting docs treat an
              -- RODC group holding the -All variant as the bug scenario,
              -- not the reverse). S-1-5-9 (Enterprise Domain Controllers,
              -- a well-known SID, not a domain-relative RID) is also a
              -- confirmed by-design default holder of the full
              -- replication right set. Deliberately does NOT exclude the
              -- "Domain Controllers" group (RID 516) itself -- Microsoft's
              -- own documentation explicitly and repeatedly instructs
              -- that group's replication rights be CLEARED, not granted
              -- (Event IDs 1979-1983 exist specifically to detect and
              -- flag this exact condition as a default-security-descriptor
              -- anomaly), so a finding there is a genuine anomaly worth
              -- surfacing, not a default to suppress.
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544' OR do2.object_sid LIKE '%%-498'
                   OR do2.object_sid = 'S-1-5-9')
            UNION
            SELECT c.object_guid
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_domain_controller
        ),
        dcsync_rights AS (
            SELECT
                a.trustee_sid,
                bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes,
                bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes_all
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                          '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
            GROUP BY a.trustee_sid
        )
        SELECT
            'fail' AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, dr.trustee_sid)
                || ' holds DCSync replication rights on the domain root ('
                || CASE WHEN dr.has_get_changes AND dr.has_get_changes_all
                        THEN 'both DS-Replication-Get-Changes and -All'
                        ELSE 'only ' || (CASE WHEN dr.has_get_changes
                                              THEN 'DS-Replication-Get-Changes'
                                              ELSE 'DS-Replication-Get-Changes-All' END)
                   END
                || ')' AS summary,
            jsonb_build_object(
                'trustee_sid', dr.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'has_get_changes', dr.has_get_changes,
                'has_get_changes_all', dr.has_get_changes_all
            ) AS detail
        FROM dcsync_rights dr
        JOIN directory_object do2
            ON do2.object_sid = dr.trustee_sid AND do2.client_id = %(client_id)s
        WHERE NOT EXISTS (
            SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid
        )
    """,
}
