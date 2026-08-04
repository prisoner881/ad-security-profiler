"""
Plugin 9001: Dangerous Rights on an Organizational Unit Held by an Unexpected Principal

Same pattern as plugins 5002 (AdminSDHolder) and 5003 (domain root),
applied per-OU: GenericAll, GenericWrite, WriteDacl, or WriteOwner on
an OU is functionally equivalent to full control over every object
within it -- new accounts created there, existing ones modified,
computer objects reconfigured for delegation, anything. OU delegation
is one of the more common real-world privilege-escalation paths this
project had no visibility into before Organizational Unit collection
existed: a broad grant made once for a legitimate reason (a help desk
team needing to manage one department's computers, say) that's never
revisited, or was scoped more broadly than intended from the start.

Unlike domain root/AdminSDHolder, there's no fixed, universal "this OU
should only ever be touched by these specific principals" answer --
every organization's OU structure and delegation model is different.
This finding flags anything beyond the same baseline well-known
holders excluded elsewhere in this project (Domain Admins, Enterprise
Admins, Administrators, SYSTEM); a security team reviewing results
will need to apply their own knowledge of what delegation is
legitimate for their specific OU structure.
"""

PLUGIN = {
    "plugin_id": 9001,
    "category": "Organizational Units",
    "name": "Dangerous Rights on an Organizational Unit Held by an Unexpected Principal",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Confirm whether this grant is a deliberate, understood "
        "delegation (e.g. a help desk team scoped to manage computers "
        "within this specific OU) or leftover/overly broad. Review via "
        "the OU's own Security tab in Active Directory Users and "
        "Computers (enable Advanced Features to see it), or "
        "`dsacls \"<OU DN>\" /R <trustee>` to remove a specific grant. "
        "GenericAll/WriteDacl on an OU is equivalent to full control "
        "over everything within it -- if the underlying need is "
        "narrower (e.g. only resetting passwords, or only managing "
        "computer objects specifically), delegate that specific, "
        "narrower right instead via the Delegation of Control Wizard."
    ),
    "control_id": "ACL-901",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
        {"title": "BloodHound (SpecterOps): WriteDacl edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-dacl"},
    ],
    "description": (
        "Same pattern as plugins 5002/5003 (AdminSDHolder/domain root), "
        "applied per-OU: GenericAll, GenericWrite, WriteDacl, or "
        "WriteOwner on an OU is functionally equivalent to full control "
        "over every object within it. OU delegation is one of the more "
        "common real-world privilege-escalation paths -- a broad grant "
        "made once for a legitimate, narrower reason, never revisited. "
        "Excludes the same baseline well-known holders (Domain Admins, "
        "Enterprise Admins, Administrators, SYSTEM) used elsewhere in "
        "this project; unlike domain root/AdminSDHolder there's no "
        "universal answer for what else is expected, since every "
        "organization's OU delegation model differs."
    ),
    "base_severity": "high",
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
            SELECT a.object_guid AS ou_guid, a.trustee_sid, a.access_mask,
                   (a.access_mask & 268435456) != 0 AS is_generic_all,
                   (a.access_mask & 1073741824) != 0 AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN ad_ou o ON o.object_guid = a.object_guid AND o.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
        ),
        unexpected_holders AS (
            SELECT da.ou_guid, da.trustee_sid,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_class AS trustee_object_class,
                   da.access_mask,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN da.is_generic_all THEN 'GenericAll' END),
                        (CASE WHEN da.is_generic_write THEN 'GenericWrite' END),
                        (CASE WHEN da.is_write_dacl THEN 'WriteDacl' END),
                        (CASE WHEN da.is_write_owner THEN 'WriteOwner' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label
            FROM dangerous_aces da
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = da.trustee_sid AND trustee_do.client_id = %(client_id)s
            WHERE NOT EXISTS (
                SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid
            )
        ),
        -- [fix, caught via a real production crash at large scale (525
        -- OUs) that this project's own small test lab never exposed]
        -- identity_guid is the OU's object_guid, not the trustee's --
        -- the original version produced one row per unexpected
        -- trustee, and any OU with more than one over-delegated
        -- principal (routine at real-world scale, even if never
        -- exercised by a 1-OU test lab) collided on identity_guid.
        -- Aggregated here instead: one finding per OU, listing every
        -- unexpected trustee and what they hold.
        aggregated AS (
            SELECT ou_guid,
                   array_agg(trustee_label || ' (' || rights_label || ')' ORDER BY trustee_label) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'rights', rights_label
                   ) ORDER BY trustee_label) AS holder_details,
                   count(*) AS holder_count
            FROM unexpected_holders
            GROUP BY ou_guid
        )
        SELECT
            'fail' AS status,
            a.ou_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on OU "'
                || o.ou_name || '": ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'ou_name', o.ou_name,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_ou o ON o.object_guid = a.ou_guid AND o.valid_to IS NULL
    """,
}
