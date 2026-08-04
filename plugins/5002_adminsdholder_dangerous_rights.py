"""
Plugin 5002: Dangerous Rights on AdminSDHolder Held by an Unexpected Principal

AdminSDHolder's own ACL is the TEMPLATE the SDProp process periodically
copies onto every "protected" object (members of Domain Admins,
Enterprise Admins, Administrators, and the other AdminSDHolder-protected
groups already established in plugins 3005/1025). A dangerous right
granted here doesn't just affect AdminSDHolder itself -- it propagates
to every protected object the next time SDProp runs (by default, every
60 minutes), making this one of the highest-leverage single objects in
the entire domain to check.

Excludes the well-known, expected holders (Domain Admins, Enterprise
Admins, Administrators, SYSTEM).

A trustee SID that doesn't resolve to a collected directory_object is
not flagged as an individual finding here -- control_evidence_fact.
object_guid has a hard foreign key against directory_object, matching
the same "count but don't individually report unresolved references"
precedent already established throughout this project.
"""

PLUGIN = {
    "plugin_id": 5002,
    "category": "ACLs",
    "name": "Dangerous Rights on AdminSDHolder Held by an Unexpected Principal",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Remove the grant unless it's a deliberate, understood exception "
        "(`dsacls \"CN=AdminSDHolder,CN=System,DC=...\" /R <trustee>`, or "
        "via ADSI Edit's Security tab). Because SDProp copies "
        "AdminSDHolder's ACL onto every protected object roughly hourly, "
        "an unexpected grant here is effectively a standing grant on "
        "every current and future member of Domain Admins, Enterprise "
        "Admins, and the other protected groups -- treat this with the "
        "same urgency as finding the grant directly on Domain Admins "
        "itself."
    ),
    "control_id": "ACL-002",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "AdminSDHolder's ACL is the template the SDProp process "
        "periodically (by default hourly) copies onto every protected "
        "object -- members of Domain Admins, Enterprise Admins, "
        "Administrators, and the other AdminSDHolder-protected groups. "
        "A dangerous right granted here doesn't just affect "
        "AdminSDHolder itself; it propagates to every protected object "
        "on the next SDProp cycle, making this one of the "
        "highest-leverage single objects in the domain to check. Flags "
        "GenericAll, GenericWrite, WriteDacl, and WriteOwner "
        "specifically -- rights that let the holder grant themselves or "
        "others further access, not read or narrowly-scoped write "
        "rights. Excludes the well-known, expected holders (Domain "
        "Admins, Enterprise Admins, Administrators, SYSTEM)."
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
            JOIN directory_object cont ON cont.object_guid = a.object_guid AND cont.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND cont.object_class = 'container'
              AND cont.dn_current ILIKE 'CN=AdminSDHolder,%%'
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
                || ' on AdminSDHolder' AS summary,
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
