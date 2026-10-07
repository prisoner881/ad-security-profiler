"""
Plugin 10090: Federated Domain Trust Is Risky

For each federated domain's federation configuration
(entra_domain_federation, source federation: /domains/{id}/
federationConfiguration, Domain.Read.All) reports settings that make a
forged token (Golden SAML) more damaging or the trust fragile:

- federatedIdpMfaBehavior 'acceptIfMfaDoneByFederatedIdp' -> high: Entra
  accepts the MFA claim in the federated token, so anyone holding the
  token-signing key can mint a token for any user of the domain that also
  satisfies Conditional Access MFA. Critical when the domain is the
  tenant's default domain (entra_domain.is_default; source domains,
  enrichment only).
- federatedIdpMfaBehavior NULL -> high: not set means the legacy
  SupportsMfa flag governs, which this collector cannot read; Microsoft
  documents the legacy behaviour as accepting MFA from the IdP when
  SupportsMfa is true. Reported with that uncertainty in
  detail.mfa_behavior_note.
- token-signing certificate expired, or expiring within 30 days of the
  Entra collection -> high (sign-in outage, or a hurried rollover that is
  easy to abuse).
- token-signing certificate notBefore more than a year before the
  collection -> medium: the key has not been rolled over, so a key stolen
  long ago still works.
- nextSigningCertificate present -> low: a second key Entra already
  trusts. Normal during an AD FS automatic rollover; confirm it is the
  expected one (AA21-008A actors added their own signing certificates).
Ages are measured against entra_domain_federation.collected_at, not now().
Certificate dates NULL (the collector could not parse the certificate)
are skipped and noted.

Not judged (too uncertain without an AD FS inventory): whether the issuer
URI or passive sign-in URI host is the client's own AD FS. They are put in
detail for the reviewer.

Why: CISA AA21-008A (Solorigate / Golden SAML): actors who obtained the AD
FS token-signing key, or who added a federation trust or certificate of
their own, forged SAML tokens for any user, MFA claim included (MITRE
T1606.002, T1484.002).

One finding per domain (object_guid md5('10090:' || client_id || ':' ||
lower(domain name))), worst severity wins, every issue listed. status
'fail' at medium or above, 'warn' at low.
"""

PLUGIN = {
    "plugin_id": 10090,
    "category": "Hybrid Identity",
    "name": "Federated Domain Trust Is Risky",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10090",
    "requires_sources": ["federation"],
    "framework_tags": [
        "CISA-AA21-008A",
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-4.2.1.1",
        "ISO-27001-2022-A.8.24",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1606.002",
        "MITRE-ATTCK-T1484.002",
    ],
    "references": [
        {"title": "CISA AA21-008A: Detecting post-compromise threat activity in Microsoft cloud environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "Microsoft Graph: internalDomainFederation resource type (federatedIdpMfaBehavior)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation"},
        {"title": "Microsoft: Best practices for securing AD FS and Web Application Proxy",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs"},
        {"title": "Microsoft: AD FS certificate rollover and Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-o365-certs"},
        {"title": "MITRE ATT&CK T1606.002 Forge Web Credentials: SAML Tokens",
         "url": "https://attack.mitre.org/techniques/T1606/002/"},
        {"title": "MITRE ATT&CK T1484.002 Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
    ],
    "description": (
        "A federated domain's trust makes Golden SAML worse or is "
        "fragile: Entra accepts MFA performed by the federated IdP "
        "(federatedIdpMfaBehavior acceptIfMfaDoneByFederatedIdp, or "
        "unset/legacy) so a forged token also satisfies MFA (high; "
        "critical on the tenant's default domain); the token-signing "
        "certificate is expired or expires within 30 days (high) or has "
        "not been rolled over for more than a year (medium); a next "
        "signing certificate is already trusted (low, confirm it is "
        "expected). Issuer and sign-in URIs are listed for review. One "
        "finding per domain."
    ),
    "remediation": (
        "Set federatedIdpMfaBehavior to enforceMfaByFederatedIdp only if "
        "the IdP really enforces MFA, otherwise rejectMfaByFederatedIdp so "
        "Entra performs MFA itself: Update-MgDomainFederationConfiguration "
        "-DomainId <domain> -InternalDomainFederationId <id> "
        "-FederatedIdpMfaBehavior rejectMfaByFederatedIdp. Better, migrate "
        "the domain to managed authentication (password hash sync or "
        "PTA, staged rollout) and decommission AD FS. While federated: "
        "roll the token-signing certificate (Update-AdfsCertificate "
        "-CertificateType Token-Signing -Urgent, then "
        "Update-MgDomainFederationConfiguration with the new certificate), "
        "keep AD FS servers Tier 0, protect the DKM key, and verify any "
        "nextSigningCertificate and the issuer/sign-in URIs match your own "
        "AD FS farm."
    ),
    "base_severity": "high",
    "query": """
        WITH src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'federation' AND s.status = 'ok') AS ok
        ),
        fed AS (
            SELECT f.*, d.is_default, d.is_verified, d.authentication_type
              FROM entra_domain_federation f
              CROSS JOIN src
              LEFT JOIN entra_domain d
                ON d.client_id = f.client_id AND lower(d.domain_name) = lower(f.domain_name)
             WHERE f.client_id = %(client_id)s
               AND src.ok
        ),
        issue AS (
            SELECT f.domain_name, CASE WHEN f.is_default IS TRUE THEN 5 ELSE 4 END AS rank,
                   'MFA performed by the federated IdP is accepted (acceptIfMfaDoneByFederatedIdp)'
                   || CASE WHEN f.is_default IS TRUE THEN ' on the tenant default domain' ELSE '' END AS issue
              FROM fed f WHERE f.federated_idp_mfa_behavior = 'acceptIfMfaDoneByFederatedIdp'
            UNION ALL
            SELECT f.domain_name, 4,
                   'federatedIdpMfaBehavior is not set (legacy SupportsMfa behaviour may accept MFA from the IdP)'
              FROM fed f WHERE f.federated_idp_mfa_behavior IS NULL
            UNION ALL
            SELECT f.domain_name, 4, 'token-signing certificate has expired'
              FROM fed f WHERE f.signing_certificate_not_after < f.collected_at
            UNION ALL
            SELECT f.domain_name, 4, 'token-signing certificate expires within 30 days'
              FROM fed f
             WHERE f.signing_certificate_not_after >= f.collected_at
               AND f.signing_certificate_not_after < f.collected_at + interval '30 days'
            UNION ALL
            SELECT f.domain_name, 3, 'token-signing certificate not rolled over for more than a year'
              FROM fed f WHERE f.signing_certificate_not_before < f.collected_at - interval '1 year'
            UNION ALL
            SELECT f.domain_name, 2, 'a next token-signing certificate is already trusted (confirm it is expected)'
              FROM fed f WHERE f.next_signing_certificate_thumbprint IS NOT NULL
        ),
        agg AS (
            SELECT i.dkey, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issues
              FROM (SELECT DISTINCT lower(domain_name) AS dkey, rank, issue FROM issue) i
             GROUP BY i.dkey
        ),
        cfg AS (
            SELECT lower(f.domain_name) AS dkey, min(f.domain_name) AS domain_name,
                   bool_or(f.is_default) AS is_default,
                   bool_or(f.federated_idp_mfa_behavior IS NULL) AS mfa_unset,
                   bool_or(f.signing_certificate_not_after IS NULL OR f.signing_certificate_not_before IS NULL)
                       AS cert_dates_missing,
                   jsonb_agg(jsonb_build_object(
                       'federation_id', f.federation_id,
                       'display_name', f.display_name,
                       'issuer_uri', f.issuer_uri,
                       'passive_sign_in_uri', f.passive_sign_in_uri,
                       'active_sign_in_uri', f.active_sign_in_uri,
                       'metadata_exchange_uri', f.metadata_exchange_uri,
                       'preferred_authentication_protocol', f.preferred_authentication_protocol,
                       'federated_idp_mfa_behavior', f.federated_idp_mfa_behavior,
                       'prompt_login_behavior', f.prompt_login_behavior,
                       'signing_certificate_thumbprint', f.signing_certificate_thumbprint,
                       'signing_certificate_subject', f.signing_certificate_subject,
                       'signing_certificate_not_before', f.signing_certificate_not_before,
                       'signing_certificate_not_after', f.signing_certificate_not_after,
                       'next_signing_certificate_thumbprint', f.next_signing_certificate_thumbprint,
                       'next_signing_certificate_not_after', f.next_signing_certificate_not_after,
                       'collected_at', f.collected_at
                   ) ORDER BY f.federation_id) AS federation
              FROM fed f
             GROUP BY lower(f.domain_name)
        )
        SELECT
            CASE WHEN a.rank >= 3 THEN 'fail' ELSE 'warn' END AS status,
            md5('10090:' || %(client_id)s::text || ':' || a.dkey)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE a.rank WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Federated domain ' || c.domain_name || ': ' || a.summary_text AS summary,
            jsonb_build_object(
                'domain_name', c.domain_name,
                'is_default_domain', c.is_default,
                'issues', a.issues,
                'federation', c.federation,
                'mfa_behavior_note', CASE WHEN c.mfa_unset THEN
                    'NULL federatedIdpMfaBehavior means the legacy SupportsMfa domain setting governs; '
                    || 'it is not readable through Graph, so whether MFA claims from the IdP are accepted '
                    || 'is uncertain.' END,
                'certificate_dates_unparsed', c.cert_dates_missing,
                'uri_note', 'Issuer and sign-in URIs are not compared with on-premises AD FS; '
                    || 'confirm they point at your own federation service.'
            ) AS detail
        FROM agg a
        JOIN cfg c ON c.dkey = a.dkey
    """,
}
