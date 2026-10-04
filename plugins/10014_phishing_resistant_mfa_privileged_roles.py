"""
Plugin 10014: Phishing-Resistant MFA Not Required for Highly Privileged Roles

Reports a tenant where no enabled Conditional Access policy requires a
phishing-resistant authentication strength for the highly privileged
directory roles.

Why it matters: CISA SCuBA MS.AAD.3.6 ("Phishing-resistant MFA SHALL be
required for highly privileged roles"), OMB M-22-09 and CISA's
phishing-resistant MFA guidance. Push, SMS, voice and OTP factors are
routinely defeated by adversary-in-the-middle phishing kits and MFA
fatigue (MITRE T1557, T1621); for an administrator that is a direct tenant
takeover. FIDO2 security keys / passkeys, Windows Hello for Business and
certificate-based (multi-factor) authentication are bound to the origin and
cannot be relayed.

A policy counts when it is enabled, its conditions target the role
(conditions.users.includeRoles contains the role template id, or
includeUsers contains 'All') without excluding it (excludeRoles), it
targets all resources (applications.includeApplications contains 'All'),
and its grant controls require an authentication strength that is
phishing-resistant: the built-in "Phishing-resistant MFA" strength
(id 00000000-0000-0000-0000-000000000004), or a custom strength whose
allowedCombinations are all among fido2, windowsHelloForBusiness and
x509CertificateMultiFactor. With operator OR and another grant control
alongside (e.g. strength OR compliant device), the strength is optional and
the policy does not count.

Results: high 'fail' when Global Administrator is not covered; medium
'warn' when Global Administrator is covered but other highly privileged
roles are not (listed). Highly privileged set (shared with plugins 10012,
10018, 10019): Global, Privileged Role, Privileged Authentication,
Security, Hybrid Identity, Application, Cloud Application, Exchange,
SharePoint, User, Conditional Access, Authentication and Intune
Administrator. A custom strength whose allowedCombinations were not
returned cannot be verified: if such a policy would otherwise cover Global
Administrator, the result is a medium 'warn' instead of a fail. Users
excluded from the covering policies are listed in detail (emergency-access
exclusions are normal).

Data caveats: needs the CA "conditions" object (entra_graph_collector
0.7.0+). If any enabled policy that requires an authentication strength
lacks its conditions (older collector, or null), coverage can't be
evaluated and no row is returned. With Security Defaults alone (no
authentication strengths) the requirement is never met: Security Defaults
allows non-phishing-resistant methods. No row when no Entra posture was
collected.

Tenant-level finding: object_guid is md5('10014:' || client_id), as in
plugin 10004.
"""

PLUGIN = {
    "plugin_id": 10014,
    "category": "Hybrid Identity",
    "name": "Phishing-Resistant MFA Not Required for Highly Privileged Roles",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10014",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.6",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.1",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1557",
        "MITRE-ATTCK-T1621",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.6)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Require phishing-resistant MFA for administrators",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa"},
        {"title": "Microsoft: Conditional Access authentication strengths",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths"},
    ],
    "description": (
        "No enabled Conditional Access policy requires a phishing-"
        "resistant authentication strength (FIDO2/passkey, Windows Hello "
        "for Business, certificate-based MFA) for Global Administrator "
        "(high), or Global Administrator is covered but other highly "
        "privileged roles are not (medium, roles listed). Push, OTP and "
        "SMS factors are defeated by adversary-in-the-middle phishing, "
        "so an administrator protected only by them can be taken over "
        "(SCuBA MS.AAD.3.6). Needs the CA policy conditions (collector "
        "0.7.0+); silent when they were not collected."
    ),
    "remediation": (
        "Register phishing-resistant methods for every administrator "
        "first (FIDO2 security keys or passkeys, Windows Hello for "
        "Business, or certificate-based authentication), then create a "
        "Conditional Access policy: Users -> Select users and groups -> "
        "Directory roles = all highly privileged roles (Global, "
        "Privileged Role, Privileged Authentication, Security, Hybrid "
        "Identity, Application, Cloud Application, Exchange, SharePoint, "
        "User, Conditional Access, Authentication, Intune Administrator); "
        "exclude only the emergency-access accounts; Target resources = "
        "All resources; Grant = Require authentication strength -> "
        "Phishing-resistant MFA. Test report-only, then switch it On. "
        "Do not combine the strength with other grant controls under "
        "'Require one of the selected controls'."
    ),
    "base_severity": "high",
    "query": """
        WITH hp_role(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator')
        ),
        posture AS (
            SELECT sp.client_id, COALESCE(sp.security_defaults_enabled, FALSE) AS sd, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   jsonb_typeof(p->'conditions') = 'object' AS evaluable,
                   p->'grant_controls'->'authenticationStrength' AS strength,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                        THEN p->'conditions'->'users'->'includeUsers' ELSE '[]'::jsonb END AS inc_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeRoles') = 'array'
                        THEN p->'conditions'->'users'->'includeRoles' ELSE '[]'::jsonb END AS inc_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                        THEN p->'conditions'->'users'->'excludeUsers' ELSE '[]'::jsonb END AS ex_users,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps,
                   -- strength is mandatory: AND, or it is the only grant control
                   (upper(COALESCE(p->'grant_controls'->>'operator', 'OR')) = 'AND'
                    OR (CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                             THEN jsonb_array_length(p->'grant_controls'->'builtInControls') ELSE 0 END
                        + CASE WHEN jsonb_typeof(p->'grant_controls'->'customAuthenticationFactors') = 'array'
                               THEN jsonb_array_length(p->'grant_controls'->'customAuthenticationFactors') ELSE 0 END
                        + CASE WHEN jsonb_typeof(p->'grant_controls'->'termsOfUse') = 'array'
                               THEN jsonb_array_length(p->'grant_controls'->'termsOfUse') ELSE 0 END) = 0) AS strict
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' = 'enabled'
               AND jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object'
        ),
        graded AS (
            SELECT pl.*,
                   CASE WHEN pl.strength->>'id' = '00000000-0000-0000-0000-000000000004' THEN 'yes'
                        WHEN jsonb_typeof(pl.strength->'allowedCombinations') = 'array'
                             AND jsonb_array_length(pl.strength->'allowedCombinations') > 0
                        THEN CASE WHEN NOT EXISTS (
                                      SELECT 1 FROM jsonb_array_elements_text(pl.strength->'allowedCombinations') c
                                       WHERE c NOT IN ('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor'))
                                  THEN 'yes' ELSE 'no' END
                        ELSE 'unknown' END AS phish_resistant
              FROM pol pl
        ),
        coverage AS (
            -- (policy, role) pairs where a strict, all-resources policy targets the role
            SELECT g.id, g.name, g.phish_resistant, g.ex_users, r.role_template_id, r.role_name
              FROM graded g
              JOIN hp_role r ON (g.inc_users ? 'All' OR g.inc_roles ? r.role_template_id)
                            AND NOT g.ex_roles ? r.role_template_id
             WHERE g.evaluable AND g.strict AND g.all_apps AND g.phish_resistant <> 'no'
        ),
        state AS (
            SELECT po.client_id, po.sd,
                   EXISTS (SELECT 1 FROM pol WHERE NOT evaluable) AS unevaluable,
                   EXISTS (SELECT 1 FROM coverage WHERE phish_resistant = 'yes'
                            AND role_template_id = '62e90394-69f5-4237-9190-012177145e10') AS ga_covered,
                   EXISTS (SELECT 1 FROM coverage WHERE phish_resistant = 'unknown'
                            AND role_template_id = '62e90394-69f5-4237-9190-012177145e10') AS ga_unknown,
                   (SELECT string_agg(r.role_name, ', ' ORDER BY r.role_name) FROM hp_role r
                     WHERE NOT EXISTS (SELECT 1 FROM coverage c WHERE c.phish_resistant = 'yes'
                                         AND c.role_template_id = r.role_template_id)) AS uncovered,
                   (SELECT jsonb_agg(r.role_name ORDER BY r.role_name) FROM hp_role r
                     WHERE NOT EXISTS (SELECT 1 FROM coverage c WHERE c.phish_resistant = 'yes'
                                         AND c.role_template_id = r.role_template_id)) AS uncovered_list,
                   (SELECT jsonb_agg(DISTINCT c.name ORDER BY c.name) FROM coverage c
                     WHERE c.phish_resistant = 'yes') AS covering_policies,
                   (SELECT jsonb_agg(DISTINCT c.name ORDER BY c.name) FROM coverage c
                     WHERE c.phish_resistant = 'unknown') AS unverifiable_strength_policies,
                   (SELECT jsonb_agg(DISTINCT u ORDER BY u) FROM coverage c
                     CROSS JOIN LATERAL jsonb_array_elements_text(c.ex_users) u
                     WHERE c.phish_resistant = 'yes') AS excluded_users
              FROM posture po
        )
        SELECT
            CASE WHEN NOT s.ga_covered AND NOT s.ga_unknown THEN 'fail' ELSE 'warn' END AS status,
            md5('10014:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN NOT s.ga_covered AND NOT s.ga_unknown THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE WHEN s.ga_covered
                 THEN 'Phishing-resistant MFA is required for Global Administrator but not for: '
                      || COALESCE(s.uncovered, '')
                 WHEN s.ga_unknown
                 THEN 'Phishing-resistant MFA for highly privileged roles cannot be verified -- '
                      || 'the covering policy uses a custom authentication strength whose methods were not collected'
                 ELSE 'No enabled Conditional Access policy requires phishing-resistant MFA for '
                      || 'Global Administrator (or the other highly privileged roles)'
            END AS summary,
            jsonb_build_object(
                'security_defaults_enabled', s.sd,
                'roles_not_covered', s.uncovered_list,
                'covering_policies', s.covering_policies,
                'unverifiable_strength_policies', s.unverifiable_strength_policies,
                'excluded_users_in_covering_policies', s.excluded_users
            ) AS detail
        FROM state s
        WHERE NOT s.unevaluable
          AND s.uncovered IS NOT NULL
    """,
}
