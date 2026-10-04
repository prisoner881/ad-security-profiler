"""
Plugin 11014: Certificate Template Security Settings or Permissions Changed

Change Detection companion to the 6xxx AD CS plugins (ESC1-ESC15) and to
11006 (template newly published). Those report templates that are
dangerous now; this one reports that a template -- published or not --
changed since the previous successful collection run in a way that
matters for certificate abuse:
- msPKI-Enrollment-Flag (manager approval, ...), msPKI-Certificate-Name-Flag
  (ENROLLEE_SUPPLIES_SUBJECT -- ESC1), pKIExtendedKeyUsage (client
  authentication / any purpose -- ESC1/ESC2/ESC3), msPKI-Template-Schema-Version
  (v1 templates -- ESC15), msPKI-RA-Signature (authorized signatures) or
  msPKI-Certificate-Policy (issuance policies -- ESC13); or
- a new allow ACE granting enrollment (Certificate-Enrollment,
  Certificate-AutoEnrollment, All Extended Rights) or write/control
  (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteProperty -- ESC4)
  on the template.

Why: an attacker with write access to a template (ESC4) typically
rewrites it into an ESC1 shape, requests a certificate as a Domain Admin,
and restores the template afterwards (SpecterOps "Certified Pre-Owned";
Certipy 'template -save-old'). A collection run that catches the window
-- or the lingering ACE -- is the only directory-side evidence. MITRE
ATT&CK T1649 (Steal or Forge Authentication Certificates).

Comparison: the current version against the version current at the
previous succeeded sync_run (11002's lookup), on the listed columns
only; enrollment and name flags and EKUs are compared exactly (EKUs as
a sorted set, NULL = no EKU = any purpose). schema_version and
certificate_policy_oids (collector 0.5.4) and ra_signature_count
(0.5.15) were added later: a NULL in the previous version counts as
"not collected" unless that version was written by a collector that
already stored the column. The columns schema v38 adds (minimal key
size, private key flag) are not compared, so the v38 rescan does not
produce findings. New ACEs are decided as in plugins 11007/11010: only
access bits the trustee did not already hold at the previous run with
the same object type count, inheritance-flag-only reopenings are
ignored, and templates with no ACL edge at the previous run are skipped.

Severity: high. Critical (fail) when the change makes the template
ESC1-shaped (enrollee supplies subject + client-authentication capable +
no manager approval + no authorized signatures) and it was not before,
or when an ESC1-shaped template gains an enrollment or write right for a
principal other than the default administrative SIDs. One row per
template. Suppressed on a client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11014,
    "category": "Change Detection",
    "name": "Certificate Template Security Settings or Permissions Changed",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11014",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-800-53-SC-17", "NIST-800-53-IA-5(2)", "NIST-800-53-AC-3",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-4.2.1.1",
        "CIS-CSC-8-8.11", "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32", "ISO-27001-2022-A.8.24",
        "SOC2-CC7.2", "SOC2-CC8.1", "SOC2-CC6.1",
        "HIPAA-164.308(a)(1)(ii)(D)", "HIPAA-164.312(e)(1)",
        "MITRE-ATTCK-T1649", "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned (ESC1, ESC4)",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports certificate templates (published or not) whose enrollment flags, "
        "certificate-name flags, extended key usages, schema version, required "
        "authorized signatures or issuance policies changed since the previous "
        "successful collection run, or that gained a new enrollment or write/control "
        "permission (ESC4). An attacker with write access commonly reshapes a template "
        "into ESC1, enrolls as a privileged user and restores it. Severity is high; "
        "critical when the change makes the template ESC1-shaped (enrollee-supplied "
        "subject, client-authentication capable, no manager approval, no signatures) "
        "or a non-default principal gains enrollment or write rights on an ESC1-shaped "
        "template. Values collected for the first time and the schema v38 columns are "
        "not treated as changes, and template ACLs are only compared once they have a "
        "baseline. Suppressed on a client's first collection run."
    ),
    "remediation": (
        "Confirm the change against a change record. Security event IDs 4899 "
        "(certificate template updated) and 4900 (template security updated) on the "
        "CA -- enable 'Audit Certification Services' and the CA's template auditing "
        "(certutil -setreg policy\\EditFlags +EDITF_AUDITCERTTEMPLATELOAD) -- and "
        "5136 on domain controllers identify who made it. Revert unapproved changes "
        "in the Certificate Templates console (certtmpl.msc): clear 'Supply in the "
        "request', require CA certificate manager approval, remove Client "
        "Authentication / Any Purpose EKUs, remove unexpected Enroll/Write ACEs. Then "
        "review certificates issued from the template since the change (certutil "
        "-view -restrict \"CertificateTemplate=<OID>\") and revoke any that were not "
        "requested legitimately -- a certificate issued while the template was "
        "ESC1-shaped can authenticate as its subject until it expires or is revoked."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        cur AS (
            SELECT t.*, cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_cert_template t
            CROSS JOIN prior_run pr
            JOIN directory_object_version cv
              ON cv.version_id = t.version_id AND cv.object_guid = t.object_guid
             AND cv.client_id = t.client_id AND cv.valid_from = t.valid_from
            WHERE t.client_id = %(client_id)s
              AND t.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        typed_cmp AS (
            SELECT c.object_guid, c.valid_from,
                   f.ord, f.field, f.old_v, f.new_v,
                   (p.enrollee_supplies_subject AND p.client_authentication_capable
                    AND (COALESCE(p.enrollment_flags, 0) & 2) = 0
                    AND COALESCE(p.ra_signature_count, 0) = 0) AS prev_esc1
            FROM cur c
            JOIN LATERAL (
                SELECT p.*, (regexp_match(psr.collector_version,
                                          '^([0-9]+)[.]([0-9]+)[.]([0-9]+)'))::int[] AS prev_cv
                FROM ad_cert_template p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
                LEFT JOIN sync_run psr
                  ON psr.run_id = pv.run_id_valid_from AND psr.client_id = pv.client_id
                WHERE p.object_guid = c.object_guid
                  AND p.client_id = %(client_id)s
                  AND p.valid_from < c.valid_from
                  AND pv.run_id_valid_from <= c.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) p ON TRUE
            CROSS JOIN LATERAL (VALUES
                (1, 'enrollment flags',
                 '0x' || to_hex(p.enrollment_flags), '0x' || to_hex(c.enrollment_flags),
                 p.enrollment_flags IS NOT NULL),
                (2, 'certificate name flags',
                 '0x' || to_hex(p.certificate_name_flags), '0x' || to_hex(c.certificate_name_flags),
                 p.certificate_name_flags IS NOT NULL),
                (3, 'extended key usages',
                 COALESCE((SELECT string_agg(e, ',' ORDER BY e) FROM unnest(p.extended_key_usage) e),
                          '(none: any purpose)'),
                 COALESCE((SELECT string_agg(e, ',' ORDER BY e) FROM unnest(c.extended_key_usage) e),
                          '(none: any purpose)'),
                 true),
                (4, 'schema version', p.schema_version::text, c.schema_version::text,
                 p.schema_version IS NOT NULL OR COALESCE(p.prev_cv >= ARRAY[0, 5, 4], false)),
                (5, 'authorized signatures required', p.ra_signature_count::text,
                 c.ra_signature_count::text,
                 p.ra_signature_count IS NOT NULL OR COALESCE(p.prev_cv >= ARRAY[0, 5, 15], false)),
                (6, 'issuance policies',
                 (SELECT string_agg(x, ',' ORDER BY x) FROM jsonb_array_elements_text(
                      CASE WHEN jsonb_typeof(p.certificate_policy_oids) = 'array'
                           THEN p.certificate_policy_oids ELSE '[]'::jsonb END) x),
                 (SELECT string_agg(x, ',' ORDER BY x) FROM jsonb_array_elements_text(
                      CASE WHEN jsonb_typeof(c.certificate_policy_oids) = 'array'
                           THEN c.certificate_policy_oids ELSE '[]'::jsonb END) x),
                 p.certificate_policy_oids IS NOT NULL OR COALESCE(p.prev_cv >= ARRAY[0, 5, 4], false))
            ) AS f(ord, field, old_v, new_v, comparable)
            WHERE f.comparable
              AND f.old_v IS DISTINCT FROM f.new_v
        ),
        typed_changes AS (
            SELECT tc.object_guid,
                   bool_or(tc.prev_esc1) AS prev_esc1,
                   string_agg(tc.field || ' ' || COALESCE(tc.old_v, '(not set)') || ' -> '
                              || COALESCE(tc.new_v, '(not set)'), '; ' ORDER BY tc.ord) AS change_list,
                   jsonb_agg(jsonb_build_object('setting', tc.field, 'previous_value', tc.old_v,
                                                'current_value', tc.new_v) ORDER BY tc.ord) AS changes,
                   min(tc.valid_from) AS changed_at
            FROM typed_cmp tc
            GROUP BY tc.object_guid
        ),
        acl_baselined AS (
            SELECT t.object_guid, pr.prev_run_id
            FROM ad_cert_template t
            CROSS JOIN prior_run pr
            WHERE t.client_id = %(client_id)s
              AND t.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND EXISTS (SELECT 1 FROM acl_edge b
                          WHERE b.client_id = %(client_id)s
                            AND b.object_guid = t.object_guid
                            AND b.run_id_valid_from <= pr.prev_run_id
                            AND (b.run_id_valid_to IS NULL OR b.run_id_valid_to > pr.prev_run_id))
        ),
        new_ace AS (
            SELECT x.*
            FROM (
                SELECT b.object_guid, a.trustee_sid, a.access_mask, a.object_type_guid,
                       a.inherit_only, a.valid_from,
                       a.access_mask & ~COALESCE((
                           SELECT bit_or(p.access_mask) FROM acl_edge p
                           WHERE p.client_id = %(client_id)s
                             AND p.object_guid = a.object_guid
                             AND p.trustee_sid = a.trustee_sid
                             AND p.ace_type = 'allow'
                             AND p.object_type_guid IS NOT DISTINCT FROM a.object_type_guid
                             AND p.run_id_valid_from <= b.prev_run_id
                             AND (p.run_id_valid_to IS NULL OR p.run_id_valid_to > b.prev_run_id)), 0) AS nb
                FROM acl_baselined b
                JOIN acl_edge a
                  ON a.client_id = %(client_id)s
                 AND a.object_guid = b.object_guid
                 AND a.valid_to IS NULL
                 AND a.ace_type = 'allow'
                 AND a.inherit_only IS NOT TRUE
                 AND a.run_id_valid_from > b.prev_run_id
                 AND a.run_id_valid_from <= %(run_id)s
            ) x
            -- enrollment / extended rights, GenericAll, GenericWrite, WriteDacl,
            -- WriteOwner, WriteProperty
            WHERE (x.nb & 1342964000) <> 0
        ),
        acl_named AS (
            SELECT n.*,
                   (n.trustee_sid IN ('S-1-5-32-544', 'S-1-5-18', 'S-1-5-9')
                    OR n.trustee_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(498|512|516|518|519|526|527)$')
                       AS is_default_admin,
                   COALESCE(tdo.sam_account_name,
                            CASE n.trustee_sid
                                WHEN 'S-1-1-0' THEN 'Everyone'
                                WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                WHEN 'S-1-5-7' THEN 'Anonymous Logon'
                                WHEN 'S-1-5-32-545' THEN 'BUILTIN Users'
                            END,
                            CASE WHEN n.trustee_sid ~ '-513$' THEN 'Domain Users'
                                 WHEN n.trustee_sid ~ '-515$' THEN 'Domain Computers' END,
                            n.trustee_sid) AS trustee_label,
                   array_to_string(array_remove(ARRAY[
                       CASE WHEN (n.nb & 983551) = 983551 OR (n.nb & 268435456) <> 0 THEN 'GenericAll' END,
                       CASE WHEN (n.nb & 1073741824) <> 0 THEN 'GenericWrite' END,
                       CASE WHEN (n.nb & 983551) <> 983551 AND (n.nb & 262144) <> 0 THEN 'WriteDacl' END,
                       CASE WHEN (n.nb & 983551) <> 983551 AND (n.nb & 524288) <> 0 THEN 'WriteOwner' END,
                       CASE WHEN (n.nb & 983551) <> 983551 AND (n.nb & 32) <> 0
                            THEN 'WriteProperty' || CASE WHEN n.object_type_guid IS NOT NULL
                                                         THEN ' (' || n.object_type_guid || ')' ELSE '' END END,
                       CASE WHEN (n.nb & 983551) <> 983551 AND (n.nb & 256) <> 0
                            THEN CASE n.object_type_guid::text
                                     WHEN '0e10c968-78fb-11d2-90d4-00c04f79dc55' THEN 'Enroll'
                                     WHEN 'a05b8cc2-17bc-4802-a710-e7c15ab866a2' THEN 'AutoEnroll'
                                     ELSE CASE WHEN n.object_type_guid IS NULL THEN 'AllExtendedRights'
                                               ELSE 'ExtendedRight ' || n.object_type_guid END END END
                   ], NULL), '+') AS rights_label
            FROM new_ace n
            LEFT JOIN LATERAL (
                SELECT x.sam_account_name FROM directory_object x
                WHERE x.object_sid = n.trustee_sid AND x.client_id = %(client_id)s
                ORDER BY x.is_deleted, x.object_guid LIMIT 1
            ) tdo ON TRUE
        ),
        acl_changes AS (
            SELECT an.object_guid,
                   bool_or(NOT an.is_default_admin) AS non_default_grant,
                   bool_and(an.is_default_admin) AS only_default_admins,
                   string_agg(an.trustee_label || ' (' || an.rights_label || ')', ', '
                              ORDER BY an.trustee_label, an.trustee_sid, an.rights_label) AS ace_list,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', an.trustee_sid, 'trustee', an.trustee_label,
                       'rights', an.rights_label, 'access_mask', an.access_mask,
                       'newly_granted_mask', an.nb, 'object_type_guid', an.object_type_guid,
                       'is_default_admin_sid', an.is_default_admin,
                       'change_observed_at', an.valid_from)
                       ORDER BY an.trustee_label, an.trustee_sid, an.rights_label) AS new_aces
            FROM acl_named an
            GROUP BY an.object_guid
        ),
        combined AS (
            SELECT t.object_guid, t.template_name, t.display_name, t.is_enabled,
                   t.enrollment_flags, t.certificate_name_flags, t.extended_key_usage,
                   t.schema_version, t.ra_signature_count,
                   tc.change_list, tc.changes, tc.prev_esc1,
                   ac.ace_list, ac.new_aces, ac.non_default_grant, ac.only_default_admins,
                   (t.enrollee_supplies_subject AND t.client_authentication_capable
                    AND (COALESCE(t.enrollment_flags, 0) & 2) = 0
                    AND COALESCE(t.ra_signature_count, 0) = 0) AS esc1_now,
                   (SELECT array_agg(DISTINCT es.ca_name ORDER BY es.ca_name)
                      FROM cert_template_enabled_edge e
                      JOIN ad_enrollment_service es
                        ON es.object_guid = e.ca_guid AND es.client_id = e.client_id
                       AND es.valid_to IS NULL
                     WHERE e.client_id = t.client_id AND e.template_guid = t.object_guid
                       AND e.valid_to IS NULL) AS published_on
            FROM ad_cert_template t
            JOIN directory_object tdo
              ON tdo.object_guid = t.object_guid AND tdo.client_id = t.client_id
             AND NOT tdo.is_deleted
            LEFT JOIN typed_changes tc ON tc.object_guid = t.object_guid
            LEFT JOIN acl_changes ac ON ac.object_guid = t.object_guid
            WHERE t.client_id = %(client_id)s
              AND t.valid_to IS NULL
              AND (tc.object_guid IS NOT NULL OR ac.object_guid IS NOT NULL)
        ),
        rated AS (
            SELECT c.*,
                   ((c.change_list IS NOT NULL AND c.esc1_now AND c.prev_esc1 IS NOT TRUE)
                    OR (c.ace_list IS NOT NULL AND c.esc1_now AND c.non_default_grant))
                       AS became_esc1
            FROM combined c
        )
        SELECT
            CASE WHEN r.became_esc1 THEN 'fail' ELSE 'warn' END AS status,
            r.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN r.became_esc1 THEN 'critical' ELSE 'high' END AS fd_severity,
            'Certificate template "' || COALESCE(r.display_name, r.template_name, r.object_guid::text)
                || '" ('
                || CASE WHEN r.published_on IS NOT NULL
                        THEN 'published on ' || array_to_string(r.published_on, ', ')
                        ELSE 'not published' END
                || ') changed since the previous collection run: '
                || array_to_string(array_remove(ARRAY[
                       r.change_list,
                       CASE WHEN r.ace_list IS NOT NULL THEN 'new permissions: ' || r.ace_list END
                   ], NULL), '; ')
                || CASE WHEN r.became_esc1
                        THEN ' -- the template is now ESC1-shaped (enrollee-supplied subject, '
                             'client-authentication capable, no approval, no signatures)'
                             || CASE WHEN r.published_on IS NULL
                                     THEN ' but is not currently published' ELSE '' END
                        ELSE '' END AS summary,
            jsonb_build_object(
                'template_name', r.template_name,
                'display_name', r.display_name,
                'published_on_cas', to_jsonb(r.published_on),
                'setting_changes', r.changes,
                'new_aces', r.new_aces,
                'esc1_shaped_now', r.esc1_now,
                'esc1_shaped_before', r.prev_esc1,
                'became_esc1_exploitable', r.became_esc1,
                'enrollment_flags', r.enrollment_flags,
                'certificate_name_flags', r.certificate_name_flags,
                'extended_key_usage', to_jsonb(r.extended_key_usage),
                'schema_version', r.schema_version,
                'ra_signature_count', r.ra_signature_count,
                'corroborating_event_ids', jsonb_build_array(4899, 4900, 5136)
            ) AS detail
        FROM rated r
    """,
}
