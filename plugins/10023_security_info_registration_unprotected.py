"""
Plugin 10023: Security-Info Registration Not Protected by Conditional Access

Reports a tenant where no enabled Conditional Access policy targets the
"Register security information" user action
(conditions.applications.includeUserActions 'urn:user:registersecurityinfo').

Why it matters: an attacker who has only a user's password (password spray,
MITRE T1110.003, or a phished password) can sign in to the security-info
page and register their own authenticator app or phone, after which every
MFA policy is satisfied by the attacker's device (T1098.005 / T1556). This
is the usual next step after a successful spray against an account that has
not registered MFA yet. A policy on the registration user action that
requires a trusted location, a compliant device, MFA or a Temporary Access
Pass closes that window. CISA SCuBA MS.AAD.3.8 ("Managed Devices SHOULD be
required to register MFA").

A policy counts when it is enabled and includes the user action with any
grant control (built-in control such as block / mfa / compliantDevice /
domainJoinedDevice, or an authentication strength); a "block outside
trusted locations" policy is a block grant and counts.

Severity:
- medium (warn) by default;
- high (fail) when the MFA registration report was read (source
  registration_details 'ok') and at least one enabled member user has not
  registered MFA (entra_user_registration.is_mfa_registered = false) --
  those accounts are open to attacker registration right now. The count is
  in detail. registration_details is enrichment only: without it the
  finding stays medium.

Result: one tenant-level row, object_guid = md5('10023:' || client_id).

Data caveats: needs the CA policy conditions (entra_graph_collector
0.7.0+). If any enabled policy has no conditions object, its user actions
can't be read and no row is returned. No row when no Entra posture was
collected. Security Defaults (when enabled) requires MFA registration
through the Authenticator app but does not protect the registration itself,
so it does not clear this check.
"""

PLUGIN = {
    "plugin_id": 10023,
    "category": "Hybrid Identity",
    "name": "Security-Info Registration Not Protected by Conditional Access",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10023",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.8",
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.005",
        "MITRE-ATTCK-T1110.003",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.8)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Securing security info registration with Conditional Access",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration"},
        {"title": "Microsoft: Conditional Access user actions",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#user-actions"},
    ],
    "description": (
        "No enabled Conditional Access policy protects the 'Register "
        "security information' user action. Anyone holding only a user's "
        "password can register their own authenticator and then pass every "
        "MFA policy as that user. High when users who have not registered "
        "MFA exist (MFA registration report collected), otherwise medium "
        "(SCuBA MS.AAD.3.8)."
    ),
    "remediation": (
        "Create a Conditional Access policy: Users = All users (exclude the "
        "emergency-access accounts and, if guests cannot meet it, guests); "
        "Target resources -> User actions -> Register security information; "
        "Conditions -> Locations: Any location, exclude All trusted "
        "locations; Grant = Block access -- or, instead of the location "
        "condition, Grant = Require device to be marked as compliant / "
        "Microsoft Entra hybrid joined, or require MFA (new users onboard "
        "with a Temporary Access Pass, which satisfies MFA). Test "
        "report-only, then switch it On. Get users who have not registered "
        "MFA to do so promptly (Entra admin center -> Authentication methods "
        "-> User registration details)."
    ),
    "base_severity": "medium",
    "query": """
        WITH posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   p->>'state' AS state,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   COALESCE(p->'conditions'->'applications'->'includeUserActions', '[]'::jsonb)
                       ? 'urn:user:registersecurityinfo' AS reg_action,
                   (COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                                                     THEN p->'grant_controls'->'builtInControls' END), 0) > 0
                    OR COALESCE(jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object', FALSE))
                       AS has_grant
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' IN ('enabled', 'enabledForReportingButNotEnforced')
        ),
        reg_ok AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'registration_details' AND s.status = 'ok') AS ok
        ),
        no_mfa AS (
            SELECT count(*) AS n
              FROM entra_user_registration r
              JOIN entra_user u ON u.client_id = r.client_id AND u.entra_object_id = r.entra_object_id
             WHERE r.client_id = %(client_id)s
               AND r.is_mfa_registered IS FALSE
               AND u.account_enabled IS TRUE
               AND u.user_type = 'Member'
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM pol WHERE state = 'enabled' AND NOT evaluable) AS unevaluable,
                   EXISTS (SELECT 1 FROM pol WHERE state = 'enabled' AND evaluable AND reg_action AND has_grant)
                       AS protected,
                   (SELECT jsonb_agg(jsonb_build_object('policy', p.name, 'id', p.id, 'state', p.state,
                                                        'has_grant_control', p.has_grant)
                                     ORDER BY p.name, p.id)
                      FROM pol p WHERE p.reg_action) AS registration_policies_not_counted,
                   (SELECT ok FROM reg_ok) AS registration_details_ok,
                   CASE WHEN (SELECT ok FROM reg_ok) THEN (SELECT n FROM no_mfa) END AS enabled_members_without_mfa
              FROM posture po
        )
        SELECT
            CASE WHEN COALESCE(s.enabled_members_without_mfa, 0) > 0 THEN 'fail' ELSE 'warn' END AS status,
            md5('10023:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN COALESCE(s.enabled_members_without_mfa, 0) > 0 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Security-info registration is not protected -- no enabled Conditional Access policy covers the '
                || '''Register security information'' user action'
                || CASE WHEN COALESCE(s.enabled_members_without_mfa, 0) > 0
                        THEN ', and enabled users without registered MFA exist' ELSE '' END AS summary,
            jsonb_build_object(
                'registration_details_collected', s.registration_details_ok,
                'enabled_members_without_mfa', s.enabled_members_without_mfa,
                'registration_policies_not_counted', s.registration_policies_not_counted
            ) AS detail
        FROM state s
        WHERE NOT s.unevaluable
          AND NOT s.protected
    """,
}
