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
"""

PLUGIN = {
    "plugin_id": 10004,
    "category": "Hybrid Identity",
    "name": "No MFA Enforcement via Security Defaults or Conditional Access",
    "version": "1.0",
    "revision_date": "2026-07-19",
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
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: What are security defaults?",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults"},
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
        "one enabled policy requires MFA as a grant control."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'No MFA enforcement mechanism active -- Security Defaults is disabled '
                || 'and no enabled Conditional Access policy requires MFA' AS summary,
            jsonb_build_object(
                'security_defaults_enabled', sp.security_defaults_enabled,
                'ca_policy_count', jsonb_array_length(sp.ca_policies),
                'enabled_ca_policy_count', (
                    SELECT count(*) FROM jsonb_array_elements(sp.ca_policies) p
                    WHERE p->>'state' = 'enabled'
                )
            ) AS detail
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND COALESCE(sp.security_defaults_enabled, FALSE) = FALSE
          AND NOT EXISTS (
                SELECT 1 FROM jsonb_array_elements(sp.ca_policies) p
                WHERE p->>'state' = 'enabled'
                  AND p->'grant_controls'->'builtInControls' ? 'mfa'
              )
    """,
}
