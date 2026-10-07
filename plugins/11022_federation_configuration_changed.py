"""
Plugin 11022: New Federated Domain or Federation Configuration Changed

Change Detection for Microsoft Entra ID. Reports domains whose federation
settings changed in the latest Entra collection: a domain that became (or
was added as) Federated, a changed issuer URI, sign-in / sign-out URIs or
federatedIdpMfaBehavior, a new token-signing certificate, a domain switched
back to Managed, and domains added or removed.

Why: adding a federated domain, or changing the issuer or signing
certificate of an existing one, is the Golden SAML / federation backdoor used
in the SolarWinds campaign (CISA AA21-008A) and by later actors: the attacker
signs SAML tokens for any user -- including MFA claims when
federatedIdpMfaBehavior accepts the IdP's MFA -- and bypasses every cloud
credential check. MITRE ATT&CK T1484.002 (Domain or Tenant Policy
Modification), T1606.002 (SAML Tokens).

Data: entra_change_history, entity_type 'federation' (one entity per tenant
domain, Managed domains included with null federation fields; content
{authentication_type, issuer_uri, passive_sign_in_uri, active_sign_in_uri,
federated_idp_mfa_behavior, prompt_login_behavior,
signing_certificate_thumbprint, next_signing_certificate_thumbprint}) and
entra_change_baseline. A version opened (valid_from) or closed (valid_to) at
the baseline's last_run_at changed in the latest collection. Suppressed on
the first collection (first_run_at = last_run_at). Findings stay open until
the next Entra collection.

Severity:
  * critical: a new Federated domain; a domain switched to Federated; issuer
    URI, passive/active sign-in URI, sign-out-less trust settings or
    federatedIdpMfaBehavior changed on a Federated domain;
  * high: only the signing certificate(s) changed (routine AD FS rollover
    looks like this, but so does a rogue certificate), or another federation
    field changed (e.g. promptLoginBehavior);
  * medium: a domain switched from Federated to Managed, or a domain removed;
  * low: a new Managed domain.
One row per domain (object_guid = md5('11022:' || client_id || ':' || domain)).
"""

PLUGIN = {
    "plugin_id": 11022,
    "category": "Change Detection",
    "name": "New Federated Domain or Federation Configuration Changed",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11022",
    "requires_sources": ["domains", "federation"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32",
        "SOC2-CC7.2", "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.002", "MITRE-ATTCK-T1606.002",
        "CISA-AA21-008A",
    ],
    "references": [
        {"title": "CISA AA21-008A: Detecting post-compromise threat activity in Microsoft cloud environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "Microsoft Graph: internalDomainFederation resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/internaldomainfederation"},
        {"title": "MITRE ATT&CK T1484.002: Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
        {"title": "MITRE ATT&CK T1606.002: Forge Web Credentials: SAML Tokens",
         "url": "https://attack.mitre.org/techniques/T1606/002/"},
    ],
    "description": (
        "Reports federation changes since the previous Entra collection: new federated "
        "domains, domains switched to Federated, changed issuer or sign-in URIs or "
        "federatedIdpMfaBehavior (critical), signing-certificate changes and other "
        "federation-field changes (high), de-federation or removed domains (medium) and new "
        "managed domains (low). A rogue federation trust lets an attacker forge tokens for "
        "any user (Golden SAML, CISA AA21-008A). Suppressed on the first Entra collection."
    ),
    "remediation": (
        "Confirm the change against an approved request: Entra audit log, service "
        "'Core Directory', activities 'Set domain authentication', 'Set federation settings "
        "on domain', 'Add verified domain'. Compare the issuer and signing certificate "
        "thumbprint with the AD FS / IdP configuration (Get-AdfsCertificate -CertificateType "
        "Token-Signing). If not approved, treat as a tenant compromise: revert the domain to "
        "Managed or restore the expected federation settings "
        "(Update-MgDomainFederationConfiguration / Remove-MgDomainFederationConfiguration), "
        "revoke refresh tokens for all users and investigate who made the change. Set "
        "federatedIdpMfaBehavior to rejectMfaByFederatedIdp where possible."
    ),
    "base_severity": "critical",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s
              AND bl.entity_type = 'federation'
              AND bl.first_run_at < bl.last_run_at
        ),
        k AS (
            SELECT DISTINCT h.entity_key
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'federation'
              AND (h.valid_from = b.last_run_at OR h.valid_to = b.last_run_at)
        ),
        chg AS (
            SELECT k.entity_key,
                   COALESCE(nv.entity_label, ov.entity_label, k.entity_key) AS label,
                   nv.content AS new_c, ov.content AS old_c,
                   CASE WHEN nv.content IS NOT NULL AND ov.content IS NULL THEN 'new'
                        WHEN nv.content IS NOT NULL THEN 'modified'
                        ELSE 'removed' END AS kind,
                   EXISTS (SELECT 1 FROM entra_change_history e
                           WHERE e.client_id = b.client_id AND e.entity_type = 'federation'
                             AND e.entity_key = k.entity_key AND e.valid_to < b.last_run_at) AS readded
            FROM k
            CROSS JOIN b
            LEFT JOIN entra_change_history nv
              ON nv.client_id = b.client_id AND nv.entity_type = 'federation'
             AND nv.entity_key = k.entity_key AND nv.valid_from = b.last_run_at AND nv.valid_to IS NULL
            LEFT JOIN entra_change_history ov
              ON ov.client_id = b.client_id AND ov.entity_type = 'federation'
             AND ov.entity_key = k.entity_key AND ov.valid_to = b.last_run_at
        ),
        cls AS (
            SELECT c.*,
                   lower(COALESCE(c.new_c->>'authentication_type', '')) = 'federated' AS new_fed,
                   lower(COALESCE(c.old_c->>'authentication_type', '')) = 'federated' AS old_fed,
                   COALESCE((SELECT array_agg(x.key ORDER BY x.key)
                             FROM (SELECT key FROM jsonb_each(COALESCE(c.new_c, '{}'::jsonb))
                                   UNION
                                   SELECT key FROM jsonb_each(COALESCE(c.old_c, '{}'::jsonb))) x
                             WHERE c.kind = 'modified'
                               AND (c.new_c -> x.key) IS DISTINCT FROM (c.old_c -> x.key)),
                            '{}'::text[]) AS changed_keys
            FROM chg c
        ),
        sev AS (
            SELECT s.*,
                   CASE
                       WHEN s.kind = 'new' AND s.new_fed THEN 'critical'
                       WHEN s.kind = 'new' THEN 'low'
                       WHEN s.kind = 'removed' THEN 'medium'
                       WHEN s.new_fed AND NOT s.old_fed THEN 'critical'
                       WHEN s.old_fed AND NOT s.new_fed THEN 'medium'
                       WHEN s.changed_keys && ARRAY['issuer_uri', 'passive_sign_in_uri',
                                                    'active_sign_in_uri',
                                                    'federated_idp_mfa_behavior'] THEN 'critical'
                       ELSE 'high'
                   END AS severity,
                   CASE
                       WHEN s.kind = 'new' AND s.new_fed THEN
                           CASE WHEN s.readded THEN 'Federated domain re-added' ELSE 'New federated domain' END
                       WHEN s.kind = 'new' THEN
                           CASE WHEN s.readded THEN 'Managed domain re-added' ELSE 'New managed domain' END
                       WHEN s.kind = 'removed' THEN 'Domain removed'
                       WHEN s.new_fed AND NOT s.old_fed THEN 'Domain switched to Federated authentication'
                       WHEN s.old_fed AND NOT s.new_fed THEN 'Domain switched from Federated to Managed authentication'
                       WHEN s.changed_keys <@ ARRAY['signing_certificate_thumbprint',
                                                    'next_signing_certificate_thumbprint']
                           THEN 'Federation signing certificate changed'
                       ELSE 'Federation configuration changed'
                   END AS what
            FROM cls s
        )
        SELECT
            CASE WHEN s.severity IN ('critical', 'high') THEN 'fail' ELSE 'warn' END AS status,
            md5('11022:' || %(client_id)s::text || ':' || lower(s.entity_key))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            s.severity AS fd_severity,
            s.what || ': "' || s.label || '"'
                || CASE WHEN s.kind = 'modified'
                        THEN ' (' || array_to_string(s.changed_keys, ', ') || ')' ELSE '' END
                || CASE WHEN COALESCE(s.new_c, s.old_c)->>'issuer_uri' IS NOT NULL
                        THEN ', issuer ' || (COALESCE(s.new_c, s.old_c)->>'issuer_uri') ELSE '' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'domain', s.entity_key,
                'change', s.kind,
                're_added', s.kind = 'new' AND s.readded,
                'changed_keys', to_jsonb(s.changed_keys),
                'previous', s.old_c,
                'current', s.new_c,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM sev s
    """,
}
