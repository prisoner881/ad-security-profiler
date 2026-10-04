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

[v1.4] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). The rights label
names only GenericAll when it is held, since it subsumes the rest.
Inherit-only ACEs (acl_edge.inherit_only, schema v34) are skipped: they
grant nothing on the object they are stored on, only on its descendants.

[v1.5] Aggregated to one finding per trustee: a principal with two or
more dangerous ACEs on the root (e.g. WriteDacl plus GenericAll) produced
duplicate finding identities and made the whole plugin error. Also flags
write access to gPLink (f30e3bbe-...) on the root -- linking a malicious
GPO at the domain root reaches every computer and user, including DCs
(the same Tier 0 test v_privileged_principal applies). All Extended
Rights on the root is not added here: it is DCSync, reported by 5001.
"""

PLUGIN = {
    "plugin_id": 5003,
    "category": "ACLs",
    "name": "Dangerous Rights on the Domain Root Held by an Unexpected Principal",
    "version": "1.5",
    "revision_date": "2026-10-04",
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
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1003.006"],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "Direct counterpart to plugin 5002, applied to the domain root "
        "object itself. GenericAll, GenericWrite, WriteDacl, or "
        "WriteOwner on the domain root -- or write access to its gPLink "
        "attribute -- is functionally equivalent to Domain Admin: the holder can grant themselves DCSync rights, "
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
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner,
                   ((a.access_mask & 32) <> 0
                    AND a.object_type_guid = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1') AS is_write_gplink
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.client_id = a.client_id
             AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.4] inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                    -- [v1.5] write gPLink: link any GPO at the domain root
                    OR ((a.access_mask & 32) <> 0
                        AND a.object_type_guid = 'f30e3bbe-9ff0-11d1-b603-0000f80367c1')
                  )
        ),
        -- [v1.5] One row per trustee: several dangerous ACEs held by the
        -- same principal used to produce duplicate finding identities.
        per_trustee AS (
            SELECT da.trustee_sid,
                   bit_or(da.access_mask) AS access_mask,
                   array_agg(DISTINCT da.access_mask ORDER BY da.access_mask) AS access_masks,
                   bool_or(da.is_generic_all) AS is_generic_all,
                   bool_or(da.is_generic_write) AS is_generic_write,
                   bool_or(da.is_write_dacl) AS is_write_dacl,
                   bool_or(da.is_write_owner) AS is_write_owner,
                   bool_or(da.is_write_gplink) AS is_write_gplink
            FROM dangerous_aces da
            GROUP BY da.trustee_sid
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
                        (CASE WHEN da.is_generic_write AND NOT da.is_generic_all THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl AND NOT da.is_generic_all THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner AND NOT da.is_generic_all THEN 'WriteOwner' END),
                        (CASE WHEN da.is_write_gplink AND NOT da.is_generic_all
                                   AND NOT da.is_generic_write THEN 'Write gPLink' END)
                    ) AS v(x) WHERE x IS NOT NULL
                )
                || ' on the domain root' AS summary,
            jsonb_build_object(
                'trustee_sid', da.trustee_sid,
                'sam_account_name', do2.sam_account_name,
                'object_class', do2.object_class,
                'access_mask', da.access_mask,
                'access_masks', to_jsonb(da.access_masks)
            ) AS detail
        FROM per_trustee da
        JOIN directory_object do2
            ON do2.object_sid = da.trustee_sid AND do2.client_id = %(client_id)s
           AND NOT do2.is_deleted
        WHERE NOT EXISTS (
            SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid
        )
    """,
}
