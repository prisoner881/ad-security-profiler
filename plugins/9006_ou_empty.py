"""
Plugin 9006: Organizational Unit Contains No Objects

Same hygiene reasoning as plugin 3007 (empty security groups), applied
to OUs: a container with nothing in it -- no users, computers, groups,
or child OUs -- is either leftover from a reorganization that never
finished, or was created for a purpose that never materialized. Not a
security risk by itself, but unmanaged structure: any ACL delegation
or GPO links on an empty OU (see plugins 9001-9003) are pure overhead,
and an empty OU is one less thing to account for when someone new is
trying to understand the actual OU structure during a review.

[v1.1] The parent DN of each object is now derived escape-aware: the
first RDN is stripped with a regex that skips backslash-escaped
characters, so a child such as "CN=Smith\\, John,OU=Sales,..." is
attributed to OU=Sales instead of to " John,OU=Sales,..." (which made an
OU whose only children had commas in their names look empty). DNs are
compared case-insensitively, and the parent DNs are computed once in a
CTE (hash anti-join) instead of once per OU. The description and detail
now state the limitation that only collected object classes count as
contents -- users (objectCategory=person), computers (including
gMSA/sMSA), groups, OUs, GPOs and foreign security principals; an OU
holding only contacts, printQueue objects, plain containers, shared
folders and the like is reported as empty.
"""

PLUGIN = {
    "plugin_id": 9006,
    "category": "Organizational Units",
    "name": "Organizational Unit Contains No Objects",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "If this OU is genuinely no longer needed, delete it (Active "
        "Directory Users and Computers -> right-click -> Delete; "
        "protected OUs will need 'Protect object from accidental "
        "deletion' unchecked first under the Object tab with Advanced "
        "Features enabled). If it's intentionally staged for future "
        "use, that's fine -- just worth confirming it's not simply "
        "forgotten leftover structure."
    ),
    "control_id": "HYGIENE-901",
    "framework_tags": [
        "NIST-800-53-CM-2",
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
    ],
    "references": [],
    "description": (
        "Same reasoning as plugin 3007 (empty security groups), "
        "applied to OUs: a container with no users, computers, groups, "
        "or child OUs inside it is either leftover from an unfinished "
        "reorganization or created for a purpose that never "
        "materialized. Not a security risk by itself -- unmanaged "
        "structure. Any ACL delegation or GPO links on an empty OU are "
        "pure overhead. Limitation: only object classes this tool "
        "collects count as contents (users, computers including "
        "managed service accounts, groups, OUs, GPOs, foreign security "
        "principals) -- an OU holding only contacts, printers, plain "
        "containers or shared folders is also reported; check it in "
        "Active Directory Users and Computers before deleting."
    ),
    "base_severity": "info",
    "query": """
        WITH child_parent AS (
            -- [v1.1] escape-aware parent DN: strip the first RDN, skipping
            -- backslash-escaped characters (e.g. "CN=Smith\\, John,...")
            SELECT DISTINCT lower(regexp_replace(child.dn_current, '^(?:[^,\\\\]|\\\\.)*,', '')) AS parent_dn
            FROM directory_object child
            WHERE child.client_id = %(client_id)s
              AND NOT child.is_deleted
              AND child.dn_current ~ '^(?:[^,\\\\]|\\\\.)*,'
        )
        SELECT
            'warn' AS status,
            o.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'OU "' || COALESCE(o.ou_name, odo.dn_current) || '" contains no objects' AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'note', 'Only collected object classes are counted (users, computers, groups, OUs, '
                        || 'GPOs, foreign security principals); contacts, printers, containers and '
                        || 'other classes are not.'
            ) AS detail
        FROM ad_ou o
        JOIN directory_object odo ON odo.object_guid = o.object_guid AND odo.client_id = o.client_id
        WHERE o.valid_to IS NULL
          AND o.client_id = %(client_id)s
          AND NOT EXISTS (
                SELECT 1 FROM child_parent cp
                WHERE cp.parent_dn = lower(odo.dn_current)
              )
    """,
}
