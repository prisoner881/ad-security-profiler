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
"""

PLUGIN = {
    "plugin_id": 5008,
    "category": "ACLs",
    "name": "Unexpected Principal Holds Reanimate-Tombstones Rights on the Domain Root",
    "version": "1.0",
    "revision_date": "2026-07-18",
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
    "framework_tags": [],
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
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, a.trustee_sid)
                || ' holds Reanimate-Tombstones rights on the domain root' AS summary,
            jsonb_build_object(
                'trustee_sid', a.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class
            ) AS detail
        FROM acl_edge a
        JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
        JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
        WHERE a.client_id = %(client_id)s
          AND a.valid_to IS NULL
          AND a.ace_type = 'allow'
          AND a.object_type_guid = '45ec5156-db7e-47bb-b53f-dbeb2d03c40f'
          AND NOT (
                do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                OR do2.object_sid LIKE '%%-518' OR do2.object_sid = 'S-1-5-32-544'
                OR do2.object_sid = 'S-1-5-18'
              )
    """,
}
