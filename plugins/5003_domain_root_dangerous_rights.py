"""
Plugin 5003: Dangerous Rights on the Domain Root Held by an Unexpected Principal

Direct counterpart to plugin 5002 (AdminSDHolder), applied to the domain
root object itself rather than the SDProp template object. A real,
overdue gap found on a second pass through this project's own ACL work:
the domain root is arguably an even more foundational object than
AdminSDHolder to check for this, and 5002 was built without its natural
domain-root counterpart alongside it.

Flags GenericAll, GenericWrite, WriteDacl, and WriteOwner specifically --
the rights that let a holder grant themselves (or anyone) further
access, not just read/limited-write rights.
"""

PLUGIN = {
    "plugin_id": 5003,
    "category": "ACLs",
    "name": "Dangerous Rights on the Domain Root Held by an Unexpected Principal",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Remove the grant unless it's a deliberate, understood exception "
        "(`dsacls \"DC=...\" /R <trustee>`, or via ADSI Edit's Security "
        "tab on the domain root object itself). GenericAll/WriteDacl on "
        "the domain root is functionally equivalent to Domain Admin -- "
        "the holder can grant themselves any right on any object in the "
        "domain, including DCSync rights (see plugin 5001), simply by "
        "rewriting the domain root's own ACL."
    ),
    "control_id": "ACL-003",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "Direct counterpart to plugin 5002, applied to the domain root "
        "object itself. GenericAll, GenericWrite, WriteDacl, or "
        "WriteOwner on the domain root is functionally equivalent to "
        "Domain Admin: the holder can grant themselves DCSync rights, "
        "modify any downstream object's ACL, or take ownership of "
        "anything in the domain. Excludes the well-known, expected "
        "holders (Domain Admins, Enterprise Admins, Administrators, "
        "SYSTEM)."
    ),
    "base_severity": "critical",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544')
            UNION
            SELECT fsp.object_guid
            FROM ad_foreign_security_principal fsp
            WHERE fsp.client_id = %(client_id)s AND fsp.valid_to IS NULL
              AND fsp.well_known_name = 'Local System'
        ),
        dangerous_aces AS (
            SELECT a.trustee_sid, a.access_mask,
                   (a.access_mask & 268435456) != 0 AS is_generic_all,
                   (a.access_mask & 1073741824) != 0 AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
        )
        SELECT
            'fail' AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, da.trustee_sid)
                || ' holds ' || (
                    SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN da.is_generic_all THEN 'GenericAll' END),
                        (CASE WHEN da.is_generic_write THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL
                )
                || ' on the domain root' AS summary,
            jsonb_build_object(
                'trustee_sid', da.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'access_mask', da.access_mask
            ) AS detail
        FROM dangerous_aces da
        JOIN directory_object do2
            ON do2.object_sid = da.trustee_sid AND do2.client_id = %(client_id)s
        WHERE NOT EXISTS (
            SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid
        )
    """,
}
