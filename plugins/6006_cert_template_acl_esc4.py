"""
Plugin 6006: Certificate Template ACL Misconfiguration Matches ESC4

ESC4, from SpecterOps' "Certified Pre-Owned" research (and named in
Will Schroeder/Lee Christensen's original taxonomy): if a non-admin
principal holds GenericAll, GenericWrite, WriteDacl, or WriteOwner on
a certificate template OBJECT ITSELF, they can rewrite the template's
own settings -- enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, add a
client-auth-capable EKU, disable manager approval -- into an ESC1-
shaped template, then enroll against their own creation. This is a
structurally different, and generally more dangerous, finding than
plugin 6001 (ESC1): 6001 flags a template that's already misconfigured
today; this flags a template that can be TURNED INTO one by anyone
holding these rights, regardless of its current settings.

Depended on adprofiler.py v0.5.4's new ADCS ACL collection --
templates were never security-descriptor-scanned before that (6001's
own docstring documents this exact limitation, predating this
plugin). Confirmed via a focused test (impacket-built real security
descriptors, not hand-waved) that build_acl_desired_edges() correctly
picks up a dangerous ACE on a template object before writing this
query against it.

Same exclusion set as 9001/5002/5003: Domain Admins, Enterprise
Admins, Administrators, SYSTEM. Certificate template administration is
occasionally delegated to a dedicated PKI admin group -- as with OU
delegation (9001), there's no universal answer for what else is
legitimate here, so this surfaces anything beyond the baseline set for
a security team's own review.
"""

PLUGIN = {
    "plugin_id": 6006,
    "category": "Certificate Services",
    "name": "Certificate Template ACL Misconfiguration Matches ESC4",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Confirm whether this grant is a deliberate PKI administration "
        "delegation or leftover/overly broad. Review via the template's "
        "own Security tab in the Certificate Templates console "
        "(certtmpl.msc), or `dsacls \"<template DN>\" /R <trustee>` to "
        "remove a specific grant. GenericAll/WriteDacl/WriteOwner here "
        "lets the holder rewrite this template into an ESC1-shaped one "
        "at will -- treat with the same urgency as a direct ESC1 "
        "finding (plugin 6001), since the practical exploitability is "
        "equivalent, just one step removed."
    ),
    "control_id": "PKI-401",
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "A non-admin principal holds GenericAll, GenericWrite, "
        "WriteDacl, or WriteOwner on a certificate template object "
        "itself -- letting them rewrite the template into an ESC1-"
        "shaped one (enrollee-supplied subject, client-auth EKU, no "
        "manager approval) and then enroll against their own creation. "
        "Excludes the same baseline well-known holders used elsewhere "
        "in this project (Domain Admins, Enterprise Admins, "
        "Administrators, SYSTEM)."
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
            SELECT a.object_guid AS template_guid, a.trustee_sid, a.access_mask,
                   (a.access_mask & 268435456) != 0 AS is_generic_all,
                   (a.access_mask & 1073741824) != 0 AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner
            FROM acl_edge a
            JOIN ad_cert_template ct ON ct.object_guid = a.object_guid AND ct.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
        ),
        unexpected_holders AS (
            SELECT da.template_guid,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_sid AS trustee_sid,
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
        -- [fix, caught via a real production crash at large scale (70
        -- certificate templates) that this project's own small test
        -- lab never exposed] identity_guid is the template's
        -- object_guid, not the trustee's -- any template with more
        -- than one over-delegated principal collided on identity_guid.
        -- Aggregated here instead, same pattern as plugin 9001's fix.
        aggregated AS (
            SELECT template_guid,
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
            GROUP BY template_guid
        )
        SELECT
            'fail' AS status,
            a.template_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            a.holder_count || ' unexpected principal(s) hold dangerous rights on certificate template "'
                || ct.display_name || '" (ESC4): ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_cert_template ct ON ct.object_guid = a.template_guid AND ct.valid_to IS NULL
    """,
}
