"""
Plugin 10085: Unverified Tenant Domain or Domain Password Expiry Set

Reads the tenant's domains (entra_domain, Graph /domains, schema v42) and
reports, one finding per domain:
- an unverified domain (is_verified false) -> low. A custom domain added
  but never verified serves no purpose; it is clutter at best, and at worst
  a record of a name someone tried to claim (or a domain whose ownership
  lapsed) that should be reviewed and removed;
- a password expiry period on a verified root domain
  (password_validity_period_days set and not 2147483647, Graph
  passwordValidityPeriodInDays) -> low. CISA SCuBA MS.AAD.6.1: user
  passwords SHALL NOT expire (NIST SP 800-63B, OMB M-22-09): forced rotation
  produces predictable passwords and does not stop phishing or spraying.
  Follows ScubaGear's own test: only root (is_root true, or unknown),
  verified domains; NULL (the default for tenants created after October
  2021) and 2147483647 both mean "never expires". Federated domains are
  included, as in ScubaGear, and marked in detail (their users' passwords
  are governed by the on-premises policy).
Both problems on one domain are combined into one low 'warn'.

Data caveats: requires_sources ['domains']. The tenant's initial
*.onmicrosoft.com domain is always verified.

object_guid: md5('10085:' || client_id || ':' || lower(domain name)).
"""

PLUGIN = {
    "plugin_id": 10085,
    "category": "Hybrid Identity",
    "name": "Unverified Tenant Domain or Domain Password Expiry Set",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10085",
    "requires_sources": ["domains"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.6.1",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.9",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.6.1)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft Graph: domain resource type (passwordValidityPeriodInDays, isVerified)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/domain"},
        {"title": "Microsoft: Password policy recommendations for Microsoft 365",
         "url": "https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations"},
    ],
    "description": (
        "A tenant domain is unverified (review and remove it), or a verified "
        "root domain sets a password expiry period, contrary to CISA SCuBA "
        "MS.AAD.6.1 (user passwords SHALL NOT expire). Low; one finding per "
        "domain."
    ),
    "remediation": (
        "Unverified domain: verify it if it is needed (add the TXT record "
        "shown in Entra admin center -> Settings -> Domain names) or delete "
        "it (Remove-MgDomain -DomainId <name>). Password expiry: Microsoft "
        "365 admin center -> Settings -> Org settings -> Security & privacy "
        "-> Password expiration policy -> 'Set passwords to never expire', or "
        "Update-MgDomain -DomainId <name> -PasswordValidityPeriodInDays "
        "2147483647 for each root domain. Pair this with MFA and banned-"
        "password protection rather than rotation."
    ),
    "base_severity": "low",
    "query": """
        WITH d AS (
            SELECT dm.*,
                   (dm.is_verified IS FALSE) AS unverified,
                   (dm.is_verified IS TRUE AND dm.is_root IS NOT FALSE
                    AND dm.password_validity_period_days IS NOT NULL
                    AND dm.password_validity_period_days <> 2147483647) AS expiry_set
              FROM entra_domain dm
             WHERE dm.client_id = %(client_id)s
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s AND s.source = 'domains' AND s.status = 'ok')
        )
        SELECT
            'warn' AS status,
            md5('10085:' || %(client_id)s::text || ':' || lower(d.domain_name))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || d.domain_name || ': ' || concat_ws('; ',
                CASE WHEN d.unverified THEN 'not verified' END,
                CASE WHEN d.expiry_set THEN 'passwords expire after '
                     || d.password_validity_period_days || ' days' END) AS summary,
            jsonb_build_object(
                'domain_name', d.domain_name,
                'is_verified', d.is_verified,
                'is_root', d.is_root,
                'is_default', d.is_default,
                'is_initial', d.is_initial,
                'authentication_type', d.authentication_type,
                'password_validity_period_days', d.password_validity_period_days,
                'supported_services', to_jsonb(d.supported_services)
            ) AS detail
        FROM d
        WHERE d.unverified OR d.expiry_set
    """,
}
