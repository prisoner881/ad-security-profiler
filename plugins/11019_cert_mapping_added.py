"""
Plugin 11019: Explicit Certificate Mapping Added to an Existing Account

Change Detection companion to plugin 1046 (weak explicit certificate
mapping, ESC14). This one reports the event: an existing user or computer
account whose altSecurityIdentities gained one or more values since the
previous successful collection run.

Why: altSecurityIdentities maps a certificate (or a Kerberos principal of
another realm) to the account, so whoever holds a matching certificate
can authenticate as it with PKINIT / Schannel. Writing a mapping onto a
privileged account is a persistence technique that survives password
resets (MITRE ATT&CK T1098, T1649; Certipy/"ESC14"). The weak formats
named in KB5014754 -- X509:<I>issuer<S>subject (issuer + subject without
serial number), X509:<S>subject and X509:<RFC822>email -- can be
satisfied by any certificate the attacker can get issued with a matching
subject or e-mail, so a new weak mapping is especially dangerous; the
strong formats are X509:<I>..<SR> (issuer + serial number), X509:<SKI>
and X509:<SHA1-PUKEY>.

Comparison: the current ad_user / ad_computer version against the version
current at the previous succeeded sync_run (11002's lookup), on
alt_security_identities only. altSecurityIdentities is collected from
collector 0.6.0 / schema v38; before that the column is NULL for every
account, so the comparison is made only when the previous version was
itself written by the v38 collector -- marked by
cleartext_password_attributes being non-NULL (always an array, possibly
empty, from v38 on). The first v38 collection is therefore a baseline and
reports nothing. In a v38-collected previous version, NULL means "no
mappings".

Severity: high; critical when the account is Tier 0 (v_privileged_principal
or v_tier0_object) or a newly added mapping uses a weak format. Disabled
accounts are rated one level lower. One row per account. Suppressed on a
client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11019,
    "category": "Change Detection",
    "name": "Explicit Certificate Mapping Added to an Existing Account",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11019",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1649",
        "CVE-2022-26923", "CVE-2022-34691",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft KB5014754: Certificate-based authentication changes on Windows domain controllers",
         "url": "https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports existing user and computer accounts whose altSecurityIdentities "
        "(explicit certificate / Kerberos mappings) gained values since the previous "
        "successful collection run. A mapping lets the holder of a matching "
        "certificate authenticate as the account, surviving password resets. Severity "
        "is high; critical when the account is Tier 0 or a new mapping uses a weak "
        "KB5014754 format (X509:<I>..<S> without serial number, X509:<S>, "
        "X509:<RFC822>); one level lower for disabled accounts. Only previous "
        "versions collected by the schema v38 collector are compared, so the first "
        "collection of the attribute is a baseline. Suppressed on a client's first "
        "collection run."
    ),
    "remediation": (
        "Confirm the mapping against a documented smart-card or certificate "
        "enrollment. Event 5136 (attribute altSecurityIdentities) or 4738 identifies "
        "who wrote it. Remove unexplained mappings: Set-ADUser <account> -Remove "
        "@{altSecurityIdentities='<value>'}. Replace weak mappings by strong ones "
        "(X509:<I>issuer<SR>serial, X509:<SKI>, X509:<SHA1-PUKEY>) and keep domain "
        "controllers in KB5014754 Full Enforcement. If a mapping on a privileged "
        "account was not approved, find and revoke the matching certificate on the "
        "CA and review the account's PKINIT / Schannel logons (events 4768 with "
        "certificate information, 4886/4887 on the CA)."
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
        acct AS (
            SELECT 'user' AS kind, u.object_guid, u.sam_account_name, u.is_enabled,
                   u.alt_security_identities, u.version_id, u.valid_from
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND cardinality(u.alt_security_identities) > 0
            UNION ALL
            SELECT 'computer', c.object_guid, c.sam_account_name, c.is_enabled,
                   c.alt_security_identities, c.version_id, c.valid_from
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND cardinality(c.alt_security_identities) > 0
        ),
        cmp AS (
            SELECT a.*, cv.run_id_valid_from AS change_run_id, pr.prev_run_id, prev.prev_alt
            FROM acct a
            CROSS JOIN prior_run pr
            JOIN directory_object_version cv
              ON cv.version_id = a.version_id AND cv.object_guid = a.object_guid
             AND cv.client_id = %(client_id)s AND cv.valid_from = a.valid_from
            JOIN LATERAL (
                SELECT p.alt_security_identities AS prev_alt
                FROM (SELECT u.version_id, u.object_guid, u.valid_from,
                             u.alt_security_identities, u.cleartext_password_attributes
                        FROM ad_user u
                       WHERE a.kind = 'user' AND u.object_guid = a.object_guid
                         AND u.client_id = %(client_id)s
                      UNION ALL
                      SELECT k.version_id, k.object_guid, k.valid_from,
                             k.alt_security_identities, k.cleartext_password_attributes
                        FROM ad_computer k
                       WHERE a.kind = 'computer' AND k.object_guid = a.object_guid
                         AND k.client_id = %(client_id)s) p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = %(client_id)s AND pv.valid_from = p.valid_from
                WHERE p.valid_from < a.valid_from
                  AND pv.run_id_valid_from <= pr.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > pr.prev_run_id)
                  -- previous version written by the v38 collector
                  AND p.cleartext_password_attributes IS NOT NULL
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
            WHERE pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        gained AS (
            SELECT m.object_guid, m.kind, m.sam_account_name, m.is_enabled, m.valid_from,
                   m.change_run_id, m.prev_run_id, m.alt_security_identities,
                   array_agg(g.val ORDER BY g.val) AS new_mappings,
                   bool_or((g.val ~* '^X509:<I>' AND g.val !~* '<SR>')
                           OR g.val ~* '^X509:<S>'
                           OR g.val ~* '^X509:<RFC822>') AS has_weak,
                   array_agg(g.val ORDER BY g.val) FILTER (
                       WHERE (g.val ~* '^X509:<I>' AND g.val !~* '<SR>')
                          OR g.val ~* '^X509:<S>'
                          OR g.val ~* '^X509:<RFC822>') AS weak_mappings
            FROM cmp m
            CROSS JOIN LATERAL unnest(m.alt_security_identities) AS g(val)
            WHERE NOT (g.val = ANY (COALESCE(m.prev_alt, ARRAY[]::text[])))
            GROUP BY m.object_guid, m.kind, m.sam_account_name, m.is_enabled, m.valid_from,
                     m.change_run_id, m.prev_run_id, m.alt_security_identities
        ),
        tier0 AS (
            SELECT pp.object_guid FROM v_privileged_principal pp WHERE pp.client_id = %(client_id)s
            UNION
            SELECT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
        ),
        rated AS (
            SELECT g.*, t0.object_guid IS NOT NULL AS is_tier0,
                   CASE WHEN t0.object_guid IS NOT NULL OR g.has_weak THEN 4 ELSE 3 END
                   - CASE WHEN g.is_enabled IS FALSE THEN 1 ELSE 0 END AS score
            FROM gained g
            LEFT JOIN tier0 t0 ON t0.object_guid = g.object_guid
        )
        SELECT
            CASE WHEN r.score >= 4 THEN 'fail' ELSE 'warn' END AS status,
            r.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN r.score >= 4 THEN 'critical' WHEN r.score = 3 THEN 'high' ELSE 'medium' END
                AS fd_severity,
            CASE WHEN r.is_tier0 THEN 'Tier 0 ' || CASE WHEN r.kind = 'computer'
                                                        THEN 'computer account "' ELSE 'account "' END
                 ELSE CASE WHEN r.kind = 'computer' THEN 'Computer account "' ELSE 'Account "' END END
                || COALESCE(r.sam_account_name, do2.dn_current)
                || '" gained ' || cardinality(r.new_mappings)
                || ' explicit certificate mapping(s) (altSecurityIdentities) since the previous '
                   'collection run: ' || array_to_string(r.new_mappings, ', ')
                || CASE WHEN r.has_weak THEN ' -- includes a weak (KB5014754) mapping format'
                        ELSE '' END
                || CASE WHEN r.is_enabled IS FALSE THEN ' (account is disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', r.sam_account_name,
                'distinguished_name', do2.dn_current,
                'account_kind', r.kind,
                'new_mappings', to_jsonb(r.new_mappings),
                'weak_new_mappings', to_jsonb(r.weak_mappings),
                'all_current_mappings', to_jsonb(r.alt_security_identities),
                'is_tier0', r.is_tier0,
                'is_enabled', r.is_enabled,
                'change_observed_run_id', r.change_run_id,
                'baseline_run_id', r.prev_run_id,
                'change_observed_at', r.valid_from,
                'related_plugins', jsonb_build_array(1046),
                'corroborating_event_ids', jsonb_build_array(5136, 4738)
            ) AS detail
        FROM rated r
        JOIN directory_object do2
          ON do2.object_guid = r.object_guid AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
    """,
}
