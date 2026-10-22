"""
Plugin 10048: Certificate-Based Authentication Accepts Low-Affinity Certificate Bindings

Reports Microsoft Entra certificate-based authentication (CBA, the
X509Certificate method) enabled with username bindings of low affinity
and no tenant-wide requirement for high affinity.

Why: a binding maps a certificate field to a user. Low-affinity fields
(the SAN PrincipalName or RFC822Name, or the Subject) are only names: any
certificate with that name from any certification authority the tenant
trusts for CBA signs the user in. Whoever can obtain such a certificate --
an ADCS template abuse on-premises (ESC1-style enrollee-supplied subject),
a compromised or loosely run CA in the trust list -- can become any user,
including administrators. High-affinity fields (SubjectKeyIdentifier,
SHA1PublicKey, IssuerAndSerialNumber) tie the user to one specific
certificate. This is the cloud counterpart of on-premises weak certificate
mapping (plugin 1046, CVE-2022-26923 / ESC14). Purple Knight reports it.

Reported when the method's state is 'enabled', at least one binding is low
affinity (trustAffinityLevel 'low', or not set on a PrincipalName,
RFC822Name or Subject field), and authenticationModeConfiguration.
x509CertificateDefaultRequiredAffinityLevel is not 'high'. Severity:
high when the default authentication mode is x509CertificateMultiFactor
(the certificate alone satisfies MFA, so Conditional Access MFA does not
stop the impersonation), otherwise medium. requireCertificateSidAlignment
(the certificate's SID must match the user's) is shown in detail; issuer
or policy-OID rules that require high affinity for some CAs are listed.
The affinity settings are only returned by the beta authentication
methods policy: evaluated only when entra_graph_collector 0.9.0 read it
from beta (content.graph_version 'beta'), never on a v1.0 read. One tenant-level row
(object_guid md5('10048:' || client_id)).
"""

PLUGIN = {
    "plugin_id": 10048,
    "category": "Hybrid Identity",
    "name": "Certificate-Based Authentication Accepts Low-Affinity Certificate Bindings",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10048",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-IA-2",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1649",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Configure Microsoft Entra certificate-based authentication (username bindings and affinity)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-certificate-based-authentication"},
        {"title": "Microsoft Graph (beta): x509CertificateUserBinding resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/x509certificateuserbinding?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "Certificate-based authentication is enabled with low-affinity username bindings "
        "(SAN principal name, RFC822 name or subject) and no requirement for high affinity, "
        "so any certificate carrying a user's name from any CA trusted for CBA signs in as "
        "that user. High when a certificate alone satisfies MFA."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Certificate-based "
        "authentication > Configure: under Username binding, use a high-affinity field "
        "(SubjectKeyIdentifier, SHA1PublicKey or IssuerAndSerialNumber, mapped to "
        "certificateUserIds on each user) with the highest priority, and set the default "
        "affinity binding to High (or add issuer / policy-OID rules requiring High). Keep "
        "the list of CAs trusted for CBA to the ones you operate, and fix ADCS templates "
        "that let enrollees supply the subject."
    ),
    "base_severity": "medium",
    "query": """
        WITH m AS (
            SELECT ts.client_id, c AS cfg
              FROM entra_tenant_setting ts
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(ts.content->'authenticationMethodConfigurations') = 'array'
                       THEN ts.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) c
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               -- affinity is only in the beta API; a v1.0 read would look like 'low' everywhere
               AND ts.content->>'graph_version' = 'beta'
               AND c->>'id' = 'X509Certificate'
               AND lower(COALESCE(c->>'state', '')) = 'enabled'
               AND jsonb_typeof(c->'certificateUserBindings') = 'array'
        ),
        b AS (
            SELECT m.client_id, x,
                   COALESCE(lower(x->>'trustAffinityLevel'),
                            CASE WHEN x->>'x509CertificateField' IN ('PrincipalName', 'RFC822Name', 'Subject')
                                 THEN 'low' ELSE 'high' END) AS affinity
              FROM m CROSS JOIN LATERAL jsonb_array_elements(m.cfg->'certificateUserBindings') x
        ),
        e AS (
            SELECT m.client_id, m.cfg,
                   lower(COALESCE(m.cfg->'authenticationModeConfiguration'->>'x509CertificateDefaultRequiredAffinityLevel',
                                  'low')) AS default_affinity,
                   m.cfg->'authenticationModeConfiguration'->>'x509CertificateAuthenticationDefaultMode' AS default_mode,
                   (SELECT jsonb_agg(jsonb_build_object('field', b.x->>'x509CertificateField',
                                                        'user_property', b.x->>'userProperty',
                                                        'priority', b.x->'priority')
                                     ORDER BY (b.x->>'priority')::int NULLS LAST, b.x->>'x509CertificateField')
                      FROM b WHERE b.client_id = m.client_id AND b.affinity = 'low') AS low_bindings
              FROM m
        )
        SELECT
            'fail' AS status,
            md5('10048:' || e.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN e.default_mode = 'x509CertificateMultiFactor' THEN 'high' ELSE 'medium' END AS fd_severity,
            'Certificate-based authentication accepts low-affinity username bindings ('
                || (SELECT string_agg(DISTINCT x->>'field', ', ') FROM jsonb_array_elements(e.low_bindings) x)
                || ') without requiring high affinity'
                || CASE WHEN e.default_mode = 'x509CertificateMultiFactor'
                        THEN '; a certificate alone satisfies MFA' ELSE '' END AS summary,
            jsonb_build_object(
                'low_affinity_bindings', e.low_bindings,
                'default_required_affinity', e.default_affinity,
                'default_authentication_mode', e.default_mode,
                'affinity_rules', e.cfg->'authenticationModeConfiguration'->'rules',
                'require_certificate_sid_alignment', e.cfg->'requireCertificateSidAlignment',
                'certificate_authority_scopes', e.cfg->'certificateAuthorityScopes'
            ) AS detail
        FROM e
        WHERE e.low_bindings IS NOT NULL
          AND e.default_affinity <> 'high'
    """,
}
