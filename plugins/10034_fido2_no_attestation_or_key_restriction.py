"""
Plugin 10034: FIDO2 / Passkey Policy Without Attestation or Key Restrictions

Detects the FIDO2 (passkey) method enabled in the authentication methods
policy with isAttestationEnforced false, or with key restrictions not
enforced (keyRestrictions.isEnforced not true, i.e. any authenticator model
(AAGUID) may be registered).

Why: FIDO2 security keys and passkeys are the phishing-resistant method
that Conditional Access authentication strengths for administrators rely
on (SCuBA MS.AAD.3.1 / 3.6). Without attestation, Entra cannot verify the
make and model of the authenticator being registered, and without an AAGUID
allow list any authenticator -- including synced or software passkeys of
unknown assurance -- satisfies "phishing-resistant". NIST SP 800-63B AAL3
requires a verifier-trusted hardware authenticator.

Data: entra_tenant_setting 'auth_methods_policy' (schema v42; Fido2
isAttestationEnforced and keyRestrictions {isEnforced, enforcementType,
aaGuids}). requires_sources ['auth_methods_policy']. A disabled FIDO2
method is not reported (no passkeys are accepted at all).

Severity: low (warn); hardening rather than an exposure. One tenant-level
row (identity md5 of plugin and client).
"""

PLUGIN = {
    "plugin_id": 10034,
    "category": "Hybrid Identity",
    "name": "FIDO2 / Passkey Policy Without Attestation or Key Restrictions",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10034",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
    ],
    "references": [
        {"title": "Microsoft: Enable passkeys (FIDO2) for your organization",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-passkey-fido2"},
        {"title": "Microsoft: Microsoft Entra ID attestation for FIDO2 security key vendors",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-fido2-hardware-vendor"},
        {"title": "NIST SP 800-63B Digital Identity Guidelines: Authentication and Lifecycle Management",
         "url": "https://pages.nist.gov/800-63-3/sp800-63b.html"},
    ],
    "description": (
        "FIDO2 / passkeys are enabled without attestation enforcement and/or without "
        "key (AAGUID) restrictions, so any authenticator model -- including synced or "
        "software passkeys of unknown assurance -- can be registered and then satisfies "
        "phishing-resistant authentication strengths required for administrators. Low: "
        "a hardening gap, not an exposure by itself."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Passkey (FIDO2) > "
        "Configure: set 'Enforce attestation' to Yes and 'Enforce key restrictions' to "
        "Yes with Restrict specific keys = Allow and the AAGUIDs of the approved "
        "security key / authenticator models. Consider separate passkey profiles so "
        "administrators are limited to attested hardware keys. Check existing "
        "registrations first (userRegistrationDetails / Get-MgUserAuthenticationFido2Method) "
        "so users of non-approved models are not locked out."
    ),
    "base_severity": "low",
    "query": """
        WITH pol AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND jsonb_typeof(ts.content) = 'object'
        ),
        fido AS (
            SELECT pol.client_id, m,
                   CASE WHEN jsonb_typeof(m->'keyRestrictions') = 'object'
                        THEN m->'keyRestrictions' END AS key_restrictions
              FROM pol
             CROSS JOIN LATERAL jsonb_array_elements(
                   CASE WHEN jsonb_typeof(pol.content->'authenticationMethodConfigurations') = 'array'
                        THEN pol.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) m
             WHERE m->>'id' = 'Fido2'
               AND lower(COALESCE(m->>'state', '')) = 'enabled'
        ),
        scored AS (
            SELECT f.*,
                   array_remove(ARRAY[
                       CASE WHEN f.m->'isAttestationEnforced' = 'false'::jsonb
                            THEN 'attestation not enforced' END,
                       CASE WHEN f.key_restrictions IS NULL
                                 OR f.key_restrictions->'isEnforced' IS DISTINCT FROM 'true'::jsonb
                            THEN 'key restrictions not enforced' END
                   ], NULL) AS issues
              FROM fido f
        )
        SELECT
            'warn' AS status,
            md5('10034:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'FIDO2 / passkey method is enabled with ' || array_to_string(s.issues, ' and ') AS summary,
            jsonb_build_object(
                'issues', to_jsonb(s.issues),
                'is_attestation_enforced', s.m->'isAttestationEnforced',
                'key_restrictions', s.key_restrictions,
                'include_targets', s.m->'includeTargets'
            ) AS detail
        FROM scored s
        WHERE cardinality(s.issues) > 0
    """,
}
