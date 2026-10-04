"""
Plugin 10004: No MFA Enforcement via Security Defaults or Conditional Access

Security Defaults being disabled is NOT, by itself, a finding -- it's
a very common and entirely correct configuration for any organization
that has moved on to Conditional Access, which offers far more
granular control (per-application, per-location, per-role targeting)
than Security Defaults' all-or-nothing approach. Flagging "Security
Defaults is off" in isolation would be a false positive for exactly
the organizations doing this correctly.

What actually matters is whether MFA is enforced by EITHER mechanism.
This checks both together: Security Defaults enabled (in which case
MFA is enforced tenant-wide, full stop), OR at least one enabled
Conditional Access policy whose grant controls include "mfa". If
neither is true, there is genuinely no MFA enforcement mechanism
active in this tenant at all -- every sign-in, from every account
including Global Administrators, can complete with password alone.

Deliberately does not attempt to verify a Conditional Access policy's
MFA requirement actually covers all users, all applications, or
excludes no one important -- this project's Conditional Access
collection is intentionally scoped to state and grantControls only
(see entra_graph_collector.py's own comment on GRAPH_CA_POLICIES_URL).
An enabled policy with "mfa" in its grant controls is enough to clear
this specific check, even if its actual targeting has gaps a more
detailed review would need to catch separately.

[v1.1] A policy now counts as requiring MFA when its grant controls
include builtInControls 'mfa' OR an authentication strength
(grantControls.authenticationStrength -- Microsoft's current way to require
MFA / passwordless MFA / phishing-resistant MFA); previously a tenant
enforcing MFA only through authentication strengths got a critical false
positive. A policy whose operator is OR and which offers a non-MFA
alternative (e.g. 'mfa' OR compliantDevice) only satisfies MFA optionally:
when that is the ONLY kind of MFA policy, the plugin now reports a medium
warn instead of passing. Identity is now a fixed per-client object_guid
(md5 of the client id) so the policy counts in detail no longer change the
finding identity whenever an unrelated policy is added or toggled.
"""

PLUGIN = {
    "plugin_id": 10004,
    "category": "Hybrid Identity",
    "name": "No MFA Enforcement via Security Defaults or Conditional Access",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Enable MFA enforcement through one of the two available "
        "mechanisms. The fastest path for a tenant with no existing "
        "Conditional Access investment is enabling Security Defaults "
        "(Entra admin center -> Identity -> Overview -> Properties -> "
        "Manage Security defaults), which requires MFA registration and "
        "enforcement tenant-wide with no configuration needed. For a "
        "tenant that wants more granular control, create at least one "
        "enabled Conditional Access policy requiring MFA -- Microsoft's "
        "own guidance recommends starting with a policy covering all "
        "users and all applications, with explicit exclusions only for "
        "documented break-glass accounts."
    ),
    "control_id": "HYBRID-004",
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.1",
        "PCI-DSS-4.0-8.4.2",
        "PCI-DSS-4.0-8.4.3",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.4",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "CISA-SCUBA-MS.AAD.3.2",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: What are security defaults?",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults"},
        {"title": "Microsoft: Conditional Access authentication strength",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths"},
    ],
    "description": (
        "Neither Security Defaults nor any enabled Conditional Access "
        "policy is enforcing MFA -- every sign-in in this tenant, "
        "including Global Administrator sign-ins, can complete with "
        "password alone. Security Defaults being off is not itself a "
        "finding (a common, correct configuration once Conditional "
        "Access takes over that role with more granular control); this "
        "only fires when NEITHER mechanism is providing MFA enforcement "
        "at all. Does not verify a Conditional Access policy's actual "
        "targeting (which users/apps it covers) -- only that at least "
        "one enabled policy requires MFA as a grant control ('mfa' "
        "built-in control or an authentication strength). Critical "
        "when no policy requires MFA at all; medium warn when the only "
        "MFA policies offer a non-MFA alternative under an OR operator "
        "(e.g. MFA or compliant device)."
    ),
    "base_severity": "critical",
    "query": """
        WITH pol AS (
            SELECT sp.client_id,
                   p->>'display_name' AS display_name,
                   COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) AS builtin,
                   upper(COALESCE(p->'grant_controls'->>'operator', 'OR')) AS operator,
                   jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object' AS has_auth_strength,
                   COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(p->'grant_controls'->'customAuthenticationFactors') = 'array'
                                                    THEN p->'grant_controls'->'customAuthenticationFactors' END), 0) AS custom_count
              FROM entra_security_posture sp
              CROSS JOIN LATERAL jsonb_array_elements(sp.ca_policies) p
             WHERE sp.client_id = %(client_id)s
               AND p->>'state' = 'enabled'
        ),
        mfa_pol AS (
            SELECT client_id, display_name,
                   -- MFA is mandatory unless an OR offers another way through
                   (operator = 'AND'
                    OR (CASE WHEN jsonb_typeof(builtin) = 'array' THEN jsonb_array_length(builtin) ELSE 0 END
                        + CASE WHEN has_auth_strength THEN 1 ELSE 0 END + custom_count) <= 1) AS strict
              FROM pol
             WHERE builtin ? 'mfa' OR has_auth_strength IS TRUE
        ),
        state AS (
            SELECT sp.client_id, sp.security_defaults_enabled,
                   jsonb_array_length(sp.ca_policies) AS ca_policy_count,
                   (SELECT count(*) FROM pol) AS enabled_ca_policy_count,
                   EXISTS (SELECT 1 FROM mfa_pol WHERE strict) AS has_strict,
                   (SELECT jsonb_agg(display_name ORDER BY display_name) FROM mfa_pol WHERE NOT strict) AS optional_mfa_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
               AND COALESCE(sp.security_defaults_enabled, FALSE) = FALSE
        )
        SELECT
            CASE WHEN s.optional_mfa_policies IS NULL THEN 'fail' ELSE 'warn' END AS status,
            md5('10004:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.optional_mfa_policies IS NULL THEN 'critical' ELSE 'medium' END AS fd_severity,
            CASE WHEN s.optional_mfa_policies IS NULL
                 THEN 'No MFA enforcement mechanism active -- Security Defaults is disabled '
                      || 'and no enabled Conditional Access policy requires MFA'
                 ELSE 'MFA is optional -- Security Defaults is disabled and every enabled '
                      || 'Conditional Access policy requiring MFA also accepts a non-MFA grant control (OR)'
            END AS summary,
            jsonb_build_object(
                'security_defaults_enabled', s.security_defaults_enabled,
                'ca_policy_count', s.ca_policy_count,
                'enabled_ca_policy_count', s.enabled_ca_policy_count,
                'optional_mfa_policies', s.optional_mfa_policies
            ) AS detail
        FROM state s
        WHERE NOT s.has_strict
    """,
}
