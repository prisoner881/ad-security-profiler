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

[v1.3] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). The rights label
names only GenericAll when it is held, since it subsumes the rest.
Inherit-only ACEs (acl_edge.inherit_only, schema v34) are skipped: they
grant nothing on the object they are stored on, only on its descendants.

[v1.4] The summary no longer goes NULL (and the evidence write no longer
fails) for a template without a displayName: it falls back to the cn.
Trustees that are already Tier 0 -- the built-in Administrator (RID
500), AdminSDHolder-protected groups and anything in
v_privileged_principal (e.g. a Domain Admins member who created or
duplicated the template and so holds Full Control) -- are no longer
reported. WriteProperty on the template attributes that alone make it
exploitable (msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag,
pKIExtendedKeyUsage, msPKI-RA-Signature,
msPKI-Certificate-Application-Policy, msPKI-RA-Application-Policies) is
now flagged, and the template's owner (implicit WriteDacl) is reported
when directory_object.owner_sid is populated for it -- note adprofiler
does not yet store owners for templates, so that branch is dormant
until it does. Rows are aggregated per (template, trustee) first.
"""

PLUGIN = {
    "plugin_id": 6006,
    "category": "Certificate Services",
    "name": "Certificate Template ACL Misconfiguration Matches ESC4",
    "version": "1.4",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-4.2.1.1",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.3",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1649",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "A non-admin principal owns, or holds GenericAll, GenericWrite, "
        "WriteDacl, WriteOwner or write access to the enrollment "
        "settings attributes on, a certificate template object "
        "itself -- letting them rewrite the template into an ESC1-"
        "shaped one (enrollee-supplied subject, client-auth EKU, no "
        "manager approval) and then enroll against their own creation. "
        "Excludes Domain Admins, Enterprise Admins, Administrators, "
        "SYSTEM, the built-in Administrator, AdminSDHolder-protected "
        "groups and any principal already privileged per "
        "v_privileged_principal."
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
        -- Template attributes whose write alone turns a template into an
        -- ESC1/ESC2/ESC3 one (schemaIDGUIDs): msPKI-Certificate-Name-Flag,
        -- msPKI-Enrollment-Flag, pKIExtendedKeyUsage, msPKI-RA-Signature,
        -- msPKI-Certificate-Application-Policy, msPKI-RA-Application-Policies.
        dangerous_aces AS (
            SELECT a.object_guid AS template_guid, a.trustee_sid, a.access_mask,
                   ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   (((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                       OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   (a.access_mask & 262144) != 0 AS is_write_dacl,
                   (a.access_mask & 524288) != 0 AS is_write_owner,
                   ((a.access_mask & 32) <> 0
                    AND a.object_type_guid IN ('ea1dddc4-60ff-416e-8cc0-17cee534bce7',
                                               'd15ef7d8-f226-46db-ae79-b34e560bd12c',
                                               '18976af6-3b9e-11d2-90cc-00c04fd91ab1',
                                               'fe17e04b-937d-4f7e-8e0e-9292c8d5683e',
                                               'dbd90548-aa37-4202-9966-8c537ba5ce32',
                                               '3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a')) AS is_write_settings,
                   false AS is_owner
            FROM acl_edge a
            JOIN ad_cert_template ct ON ct.object_guid = a.object_guid AND ct.client_id = a.client_id
             AND ct.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.3] inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                    OR ((a.access_mask & 32) <> 0                           -- [v1.4] write a dangerous
                        AND a.object_type_guid IN ('ea1dddc4-60ff-416e-8cc0-17cee534bce7',   --   template attribute
                                                   'd15ef7d8-f226-46db-ae79-b34e560bd12c',
                                                   '18976af6-3b9e-11d2-90cc-00c04fd91ab1',
                                                   'fe17e04b-937d-4f7e-8e0e-9292c8d5683e',
                                                   'dbd90548-aa37-4202-9966-8c537ba5ce32',
                                                   '3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a'))
                  )
            UNION ALL
            -- [v1.4] The owner can always rewrite the DACL (implicit
            -- WriteDacl). Used whenever directory_object.owner_sid is
            -- populated for the template.
            SELECT ct.object_guid, tdo.owner_sid, 0, false, false, false, false, false, true
            FROM ad_cert_template ct
            JOIN directory_object tdo ON tdo.object_guid = ct.object_guid AND tdo.client_id = ct.client_id
            WHERE ct.client_id = %(client_id)s AND ct.valid_to IS NULL
              AND tdo.owner_sid IS NOT NULL
        ),
        -- [v1.4] One row per (template, trustee), and only trustees that
        -- are not Tier 0 already: not a well-known admin SID (incl. the
        -- built-in Administrator, RID 500), not an AdminSDHolder-protected
        -- group, and not in v_privileged_principal (e.g. a Domain Admins
        -- member who created or duplicated the template).
        unexpected_holders AS (
            SELECT da.template_guid,
                   COALESCE(trustee_do.sam_account_name, da.trustee_sid) AS trustee_label,
                   trustee_do.object_sid AS trustee_sid,
                   trustee_do.object_class AS trustee_object_class,
                   bit_or(da.access_mask) AS access_mask,
                   (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN bool_or(da.is_owner) THEN 'Owner' END),
                        (CASE WHEN bool_or(da.is_generic_all) THEN 'GenericAll' END),
                        (CASE WHEN bool_or(da.is_generic_write) AND NOT bool_or(da.is_generic_all) THEN 'GenericWrite' END),
                        (CASE WHEN bool_or(da.is_write_dacl) AND NOT bool_or(da.is_generic_all) THEN 'WriteDacl' END),
                        (CASE WHEN bool_or(da.is_write_owner) AND NOT bool_or(da.is_generic_all) THEN 'WriteOwner' END),
                        (CASE WHEN bool_or(da.is_write_settings) AND NOT bool_or(da.is_generic_all)
                                   AND NOT bool_or(da.is_generic_write) THEN 'WriteProperty on template settings' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS rights_label
            FROM dangerous_aces da
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = da.trustee_sid AND trustee_do.client_id = %(client_id)s
               AND NOT trustee_do.is_deleted
            WHERE NOT EXISTS (
                SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid
            )
              AND NOT (trustee_do.object_sid LIKE '%%-500' OR trustee_do.object_sid LIKE '%%-516'
                       OR trustee_do.object_sid LIKE '%%-518' OR trustee_do.object_sid = 'S-1-5-9')
              AND NOT EXISTS (SELECT 1 FROM ad_group pg
                              WHERE pg.object_guid = trustee_do.object_guid AND pg.client_id = trustee_do.client_id
                                AND pg.valid_to IS NULL AND pg.is_protected_group)
              AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                              WHERE vp.client_id = trustee_do.client_id
                                AND vp.object_guid = trustee_do.object_guid)
            GROUP BY da.template_guid, trustee_do.object_guid, trustee_do.sam_account_name,
                     da.trustee_sid, trustee_do.object_sid, trustee_do.object_class
        ),
        -- [fix, caught via a real production crash at large scale (70
        -- certificate templates) that this project's own small test
        -- lab never exposed] identity_guid is the template's
        -- object_guid, not the trustee's -- any template with more
        -- than one over-delegated principal collided on identity_guid.
        -- Aggregated here instead, same pattern as plugin 9001's fix.
        aggregated AS (
            SELECT template_guid,
                   array_agg(trustee_label || ' (' || rights_label || ')' ORDER BY trustee_label, trustee_sid) AS holder_summaries,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', trustee_sid,
                       'trustee_sam_account_name', trustee_label,
                       'trustee_object_class', trustee_object_class,
                       'access_mask', access_mask,
                       'rights', rights_label
                   ) ORDER BY trustee_label, trustee_sid) AS holder_details,
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
                || COALESCE(ct.display_name, ct.template_name, ct.object_guid::text)
                || '" (ESC4): ' || array_to_string(a.holder_summaries, '; ') AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'holders', a.holder_details
            ) AS detail
        FROM aggregated a
        JOIN ad_cert_template ct ON ct.object_guid = a.template_guid AND ct.client_id = %(client_id)s
         AND ct.valid_to IS NULL
    """,
}
