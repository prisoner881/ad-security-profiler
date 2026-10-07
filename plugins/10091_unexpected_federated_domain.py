"""
Plugin 10091: Unexpected Federated Domain

Reports federated domains (entra_domain.authentication_type 'Federated',
source domains) that look like a federation backdoor rather than the
client's own identity provider:

- the domain is federated but not verified -> high; and
- the tenant's federated domains point at more than one identity provider
  (needs source federation; enrichment) -> high for each domain on a
  minority provider (every domain when no provider has a clear majority).
  The provider is identified by the host of the passive sign-in URI
  (falling back to the issuer URI), NOT by the raw issuer URI: AD FS
  federating several domains with -SupportMultipleDomain gives each domain
  its own issuer (http://<domain>/adfs/services/trust) while they all sign
  in at the same AD FS host, so raw issuers would differ on every healthy
  multi-domain farm.

Why: the AADInternals-style backdoor (and the Solorigate actors in CISA
AA21-008A) converts a domain to federated, or adds a domain, with an
attacker-controlled IdP, then signs tokens for any user of that domain
(MITRE T1484.002, T1606.002). A second IdP that nobody expected, or a
federated domain that was never verified, is the visible trace.

Deliberately not reported: every federated domain as "present, confirm
expected" (too noisy for tenants that legitimately federate); a domain
newly converted to federated is reported by change detection (11022).

One finding per domain (object_guid md5('10091:' || client_id || ':' ||
lower(domain name))), all reasons listed. Requires source domains: no
rows when it is not 'ok'. Without source federation only the unverified
check runs and detail says so.
"""

PLUGIN = {
    "plugin_id": 10091,
    "category": "Hybrid Identity",
    "name": "Unexpected Federated Domain",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10091",
    "requires_sources": ["domains"],
    "framework_tags": [
        "CISA-AA21-008A",
        "NIST-800-53-AC-20",
        "NIST-800-53-SC-7",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-05",
        "ISO-27001-2022-A.8.20",
        "SOC2-CC6.6",
        "MITRE-ATTCK-T1484.002",
        "MITRE-ATTCK-T1606.002",
    ],
    "references": [
        {"title": "CISA AA21-008A: Detecting post-compromise threat activity in Microsoft cloud environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "Microsoft Graph: domain resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/domain"},
        {"title": "Microsoft: Multiple domain support for federating with Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-multiple-domains"},
        {"title": "MITRE ATT&CK T1484.002 Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
    ],
    "description": (
        "A federated domain is not verified, or the tenant's federated "
        "domains sign in at more than one identity provider and this "
        "domain is on a minority provider -- the trace of a federation "
        "backdoor (an attacker-controlled IdP trusted for a domain, as in "
        "CISA AA21-008A). High. Providers are compared by sign-in host, "
        "so multi-domain AD FS farms with per-domain issuers are not "
        "flagged. One finding per domain."
    ),
    "remediation": (
        "Confirm with the identity team whether the domain and its "
        "identity provider are expected (Get-MgDomain / "
        "Get-MgDomainFederationConfiguration -DomainId <domain>). If not: "
        "treat it as a compromise -- convert the domain back to managed "
        "authentication (Update-MgDomain -DomainId <domain> "
        "-AuthenticationType Managed, after removing its federation "
        "configuration with Remove-MgDomainFederationConfiguration), "
        "review the audit log for 'Set domain authentication' and "
        "'Set federation settings on domain' events and who performed "
        "them, revoke sessions of the domain's users, and review "
        "Hybrid Identity / Domain Name / Global Administrator holders."
    ),
    "base_severity": "high",
    "query": """
        WITH src AS (
            SELECT bool_or(s.source = 'domains' AND s.status = 'ok') AS domains_ok,
                   bool_or(s.source = 'federation' AND s.status = 'ok') AS fed_ok
              FROM (SELECT 1) one
              LEFT JOIN entra_collection_status s ON s.client_id = %(client_id)s
        ),
        fdom AS (
            SELECT d.domain_name, lower(d.domain_name) AS dkey, d.is_verified, d.is_default
              FROM entra_domain d, src
             WHERE d.client_id = %(client_id)s
               AND src.domains_ok
               AND d.authentication_type = 'Federated'
        ),
        fed AS (
            SELECT lower(f.domain_name) AS dkey,
                   min(lower(COALESCE(substring(f.passive_sign_in_uri from '^[A-Za-z][A-Za-z0-9+.-]*://([^/:?#]+)'),
                                      f.issuer_uri))) AS idp,
                   jsonb_agg(jsonb_build_object(
                       'federation_id', f.federation_id,
                       'issuer_uri', f.issuer_uri,
                       'passive_sign_in_uri', f.passive_sign_in_uri,
                       'active_sign_in_uri', f.active_sign_in_uri,
                       'signing_certificate_thumbprint', f.signing_certificate_thumbprint
                   ) ORDER BY f.federation_id) AS federation
              FROM entra_domain_federation f, src
             WHERE f.client_id = %(client_id)s
               AND src.fed_ok
             GROUP BY lower(f.domain_name)
        ),
        dom AS (
            SELECT fd.*, fe.idp, fe.federation
              FROM fdom fd
              LEFT JOIN fed fe ON fe.dkey = fd.dkey
        ),
        idp_count AS (
            SELECT idp, count(*) AS n FROM dom WHERE idp IS NOT NULL GROUP BY idp
        ),
        idp_stats AS (
            SELECT count(*) AS idps, max(n) AS max_n,
                   count(*) FILTER (WHERE n = (SELECT max(n) FROM idp_count)) AS idps_at_max,
                   jsonb_object_agg(idp, n) AS per_idp
              FROM idp_count
        ),
        issue AS (
            SELECT d.dkey, 'federated but not verified' AS issue
              FROM dom d WHERE d.is_verified IS FALSE
            UNION ALL
            SELECT d.dkey,
                   'signs in at identity provider ' || d.idp
                   || ', while the tenant''s federated domains use more than one identity provider'
              FROM dom d
              JOIN idp_count c ON c.idp = d.idp
              CROSS JOIN idp_stats st
             WHERE st.idps > 1
               AND (c.n < st.max_n OR st.idps_at_max > 1)
        ),
        agg AS (
            SELECT i.dkey,
                   string_agg(i.issue, '; ' ORDER BY i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.issue COLLATE "C") AS issues
              FROM issue i
             GROUP BY i.dkey
        )
        SELECT
            'fail' AS status,
            md5('10091:' || %(client_id)s::text || ':' || d.dkey)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Federated domain ' || d.domain_name || ': ' || a.summary_text AS summary,
            jsonb_build_object(
                'domain_name', d.domain_name,
                'is_verified', d.is_verified,
                'is_default_domain', d.is_default,
                'issues', a.issues,
                'identity_provider_host', d.idp,
                'federated_domains_per_identity_provider', st.per_idp,
                'federation', d.federation,
                'coverage_notes', CASE WHEN NOT src.fed_ok
                    THEN jsonb_build_array('federation configuration was not collected; '
                                           || 'identity providers could not be compared')
                    ELSE '[]'::jsonb END
            ) AS detail
        FROM agg a
        JOIN dom d ON d.dkey = a.dkey
        CROSS JOIN idp_stats st
        CROSS JOIN src
    """,
}
