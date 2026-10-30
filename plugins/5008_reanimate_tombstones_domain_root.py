"""
Plugin 5008: Unexpected Principal Holds Reanimate-Tombstones Rights on the Domain Root

The Reanimate-Tombstones extended right (rightsGuid
45EC5156-DB7E-47bb-B53F-DBEB2D03C40F, confirmed against Microsoft's
own [MS-ADTS] specification) permits restoring a deleted (tombstoned)
object -- including a previously-deleted privileged user, computer,
or group, with most of its original attributes intact. This is a
narrow, uncommon administrative right by design, and Microsoft's
default holders are limited to Domain Admins/Enterprise Admins tier
groups. An unexpected principal holding it on the domain root can
restore a deleted privileged object (a former Domain Admin account
that was supposedly removed, for instance) largely as it existed
before deletion -- a documented persistence and privilege-escalation
technique.

[v1.1] Only allow ACEs that apply to the domain root itself
(inherit_only IS NOT TRUE) and carry the CONTROL_ACCESS bit (0x100) are
counted, and results are grouped per trustee so two edges for the same
right (different masks) can't produce duplicate finding identities.
Deleted trustee objects are ignored.

[v1.2] A trustee with no directory object -- Everyone, Authenticated
Users, Anonymous Logon, Users, Network or Interactive when the domain
has no foreignSecurityPrincipal for it -- was dropped by an inner join,
so a grant to Everyone produced no finding. Such broad well-known
principals are now reported (named in the summary, object_guid NULL);
other object-less SIDs (SYSTEM, Creator Owner, Self, Enterprise Domain
Controllers) are still left out, and expected holders are matched by SID.
"""

PLUGIN = {
    "plugin_id": 5008,
    "category": "ACLs",
    "name": "Unexpected Principal Holds Reanimate-Tombstones Rights on the Domain Root",
    "version": "1.2",
    "revision_date": "2026-10-30",
    "remediation": (
        "Remove the Reanimate-Tombstones grant from the principal shown "
        "in this finding's evidence unless there is a specific, "
        "documented operational reason it needs the ability to restore "
        "deleted objects (Advanced Security Settings on the domain "
        "root -> find the entry -> Remove). Review the AD Recycle Bin "
        "or tombstone/deleted-objects container for any objects that "
        "principal may have already reanimated."
    ),
    "control_id": "ACL-008",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "Microsoft: [MS-ADTS] Reanimate-Tombstones control access right",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/af7bf236-08bc-427e-9e0a-0a0b6dc89dbd"},
    ],
    "description": (
        "The Reanimate-Tombstones extended right (rightsGuid "
        "45EC5156-DB7E-47bb-B53F-DBEB2D03C40F, confirmed against "
        "Microsoft's own [MS-ADTS] specification) permits restoring a "
        "deleted (tombstoned) object -- including a previously-deleted "
        "privileged user, computer, or group, with most of its "
        "original attributes intact. A narrow, uncommon right by "
        "design; an unexpected principal holding it on the domain root "
        "can restore a deleted privileged object largely as it existed "
        "before deletion, a documented persistence and privilege-"
        "escalation technique."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            COALESCE(do2.object_guid, md5('5008:' || %(client_id)s::text || ':' || a.trustee_sid)::uuid) AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, CASE a.trustee_sid WHEN 'S-1-1-0' THEN 'Everyone' WHEN 'S-1-5-11' THEN 'Authenticated Users' WHEN 'S-1-5-7' THEN 'Anonymous Logon' WHEN 'S-1-5-32-545' THEN 'Users' WHEN 'S-1-5-2' THEN 'Network' WHEN 'S-1-5-4' THEN 'Interactive' END, a.trustee_sid)
                || ' holds Reanimate-Tombstones rights on the domain root' AS summary,
            jsonb_build_object(
                'trustee_sid', a.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class
            ) AS detail
        FROM (
            -- [v1.1] One row per trustee; only allow ACEs that apply to
            -- the domain root itself (inherit_only IS NOT TRUE) and carry
            -- the CONTROL_ACCESS bit (0x100) grant the extended right.
            SELECT a.trustee_sid
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.client_id = a.client_id
             AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (a.access_mask & 256) <> 0
              AND a.object_type_guid = '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'
            GROUP BY a.trustee_sid
        ) a
        LEFT JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
        -- [v1.2] Trustees with no directory object (Everyone, Authenticated Users,
        -- Anonymous Logon ... when no foreignSecurityPrincipal exists for them) used
        -- to be dropped by an inner join: a broad grant produced no finding. Kept
        -- now when the SID is one of those broad well-known principals; other
        -- object-less SIDs (SYSTEM, Creator Owner, Self, Enterprise Domain
        -- Controllers ...) stay out, as before. Expected holders are tested by SID.
        WHERE (do2.object_guid IS NOT NULL OR a.trustee_sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545', 'S-1-5-2', 'S-1-5-4'))
          AND NOT (
                a.trustee_sid LIKE '%%-512' OR a.trustee_sid LIKE '%%-519'
                OR a.trustee_sid LIKE '%%-518' OR a.trustee_sid = 'S-1-5-32-544'
                OR a.trustee_sid = 'S-1-5-18'
              )
    """,
}
