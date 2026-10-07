"""
Plugin 10061: Application Certificates Expired or Long-Lived, or Credential Sprawl

Extends plugin 10005 (client secrets) to the certificates (keyCredentials)
of application registrations, and counts every live credential an
application carries. One finding per application, every issue listed,
worst severity wins.

Checks (dates judged against the snapshot's collected_at):
- a still-valid certificate whose validity period (end - start) exceeds
  365 days -> medium, status 'fail'. CISA SCuBA MS.AAD.5.7: application
  certificate lifetime SHOULD be restricted to 365 days or less; a stolen
  long-lived certificate (or its private key copied from a build server or
  key vault) stays usable for years.
- one or more expired certificates still registered -> low, 'warn': inert,
  but orphaned credential entries show the application's credentials are
  not managed, and are clutter that hides a malicious addition.
- more than 2 active credentials (unexpired client secrets + certificates)
  on one application -> low, 'warn': credential sprawl -- every extra
  credential is another thing to leak, and an attacker-added one blends in
  (MITRE T1098.001).

Why it matters: application credentials are what attackers steal or add to
act as an application without MFA (Midnight Blizzard, CISA ED 24-02).
Short lifetimes, one or two credentials per application and prompt cleanup
keep that exposure small and reviewable.

Data: entra_application.key_credentials (schema v42, the core applications
step of entra_graph_collector.py 0.8.0) and password_credentials. An older
collector stores key_credentials as '[]', so this plugin then reports only
secret sprawl -- no certificate findings. Certificates without dates are
ignored for the lifetime and expiry checks. Credentials set on service
principals are plugin 10060. Identity = the application's object id.
"""

PLUGIN = {
    "plugin_id": 10061,
    "category": "Hybrid Identity",
    "name": "Application Certificates Expired or Long-Lived, or Credential Sprawl",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10061",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.5.7",
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-12",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.9",
        "PCI-DSS-4.0-8.6.3",
        "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.7)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Security best practices for application properties in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration"},
        {"title": "Microsoft Graph: keyCredential resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/keycredential"},
        {"title": "MITRE ATT&CK T1098.001: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "An application registration has a still-valid certificate with a "
        "validity period over 365 days (medium, SCuBA MS.AAD.5.7), "
        "expired certificates still registered (low), or more than two "
        "active credentials (secrets and certificates, low). Long-lived "
        "and surplus credentials are what attackers steal, and extra "
        "entries hide an attacker-added one. One finding per application; "
        "dates are judged against the Entra snapshot's collection time."
    ),
    "remediation": (
        "For each application: remove expired certificates and any "
        "credential nobody can attribute to a running integration "
        "(Entra admin center -> App registrations -> Certificates & "
        "secrets, or Remove-MgApplicationKey / Remove-MgApplicationPassword). "
        "Re-issue long-lived certificates with a validity of 12 months or "
        "less and automate rotation (Key Vault auto-renewal), keep at most "
        "one active credential plus one during rotation, and enforce "
        "certificate and secret lifetimes with an app management policy "
        "(tenantAppManagementPolicy). Prefer managed identities or "
        "workload identity federation where the workload supports them."
    ),
    "base_severity": "medium",
    "query": """
        WITH certs AS (
            SELECT a.entra_object_id, k.ord,
                   k.value->>'key_id' AS key_id,
                   k.value->>'display_name' AS cert_display_name,
                   (k.value->>'start_date_time')::timestamptz AS start_at,
                   (k.value->>'end_date_time')::timestamptz AS end_at,
                   a.collected_at
              FROM entra_application a
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(a.key_credentials) = 'array'
                       THEN a.key_credentials ELSE '[]'::jsonb END) WITH ORDINALITY AS k(value, ord)
             WHERE a.client_id = %(client_id)s
        ),
        cert_flags AS (
            SELECT c.*,
                   c.end_at < c.collected_at AS expired,
                   (c.end_at IS NULL OR c.end_at >= c.collected_at) AS active,
                   c.end_at >= c.collected_at AND c.start_at IS NOT NULL
                       AND c.end_at - c.start_at > interval '365 days' AS long_lived
              FROM certs c
        ),
        cert_agg AS (
            SELECT f.entra_object_id,
                   count(*) FILTER (WHERE f.expired) AS expired_certs,
                   count(*) FILTER (WHERE f.active) AS active_certs,
                   count(*) FILTER (WHERE f.long_lived) AS long_lived_certs,
                   jsonb_agg(jsonb_build_object(
                       'key_id', f.key_id, 'display_name', f.cert_display_name,
                       'start_date_time', f.start_at, 'end_date_time', f.end_at,
                       'expired', COALESCE(f.expired, false),
                       'validity_days', CASE WHEN f.start_at IS NOT NULL AND f.end_at IS NOT NULL
                                             THEN extract(day FROM f.end_at - f.start_at)::int END,
                       'over_365_days', COALESCE(f.long_lived, false))
                       ORDER BY f.end_at, f.key_id COLLATE "C", f.ord) AS certificates
              FROM cert_flags f
             GROUP BY f.entra_object_id
        ),
        secret_agg AS (
            SELECT a.entra_object_id,
                   count(*) AS active_secrets
              FROM entra_application a
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(a.password_credentials) = 'array'
                       THEN a.password_credentials ELSE '[]'::jsonb END) AS p(value)
             WHERE a.client_id = %(client_id)s
               AND (p.value->>'end_date_time' IS NULL
                    OR (p.value->>'end_date_time')::timestamptz >= a.collected_at)
             GROUP BY a.entra_object_id
        ),
        apps AS (
            SELECT a.entra_object_id, a.app_id, a.display_name,
                   COALESCE(c.expired_certs, 0) AS expired_certs,
                   COALESCE(c.active_certs, 0) AS active_certs,
                   COALESCE(c.long_lived_certs, 0) AS long_lived_certs,
                   COALESCE(s.active_secrets, 0) AS active_secrets,
                   COALESCE(c.certificates, '[]'::jsonb) AS certificates
              FROM entra_application a
              LEFT JOIN cert_agg c ON c.entra_object_id = a.entra_object_id
              LEFT JOIN secret_agg s ON s.entra_object_id = a.entra_object_id
             WHERE a.client_id = %(client_id)s
        ),
        issues AS (
            SELECT entra_object_id, 2 AS rank,
                   long_lived_certs::text || ' active certificate(s) valid for more than 365 days' AS issue
              FROM apps WHERE long_lived_certs > 0
            UNION ALL
            SELECT entra_object_id, 1,
                   (active_secrets + active_certs)::text || ' active credentials (more than 2: '
                   || active_secrets::text || ' secret(s), ' || active_certs::text || ' certificate(s))'
              FROM apps WHERE active_secrets + active_certs > 2
            UNION ALL
            SELECT entra_object_id, 1,
                   expired_certs::text || ' expired certificate(s) still registered'
              FROM apps WHERE expired_certs > 0
        ),
        agg AS (
            SELECT i.entra_object_id, max(i.rank) AS rank,
                   string_agg(i.issue COLLATE "C", '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_list
              FROM issues i
             GROUP BY i.entra_object_id
        )
        SELECT
            CASE WHEN g.rank = 2 THEN 'fail' ELSE 'warn' END AS status,
            a.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.rank = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application "' || COALESCE(a.display_name, a.app_id::text, a.entra_object_id::text)
                || '": ' || g.issue_text AS summary,
            jsonb_build_object(
                'application_id', a.entra_object_id,
                'app_id', a.app_id,
                'display_name', a.display_name,
                'issues', g.issue_list,
                'active_secrets', a.active_secrets,
                'active_certificates', a.active_certs,
                'expired_certificates', a.expired_certs,
                'certificates', a.certificates
            ) AS detail
        FROM agg g
        JOIN apps a ON a.entra_object_id = g.entra_object_id
    """,
}
