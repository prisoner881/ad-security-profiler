"""
Plugin 10025: Risk-Based Conditional Access Policies Missing

Reports, as separate rows, a tenant with no enabled Conditional Access
policy acting on:
- high USER risk (conditions.userRiskLevels contains 'high') with grant
  Block, or MFA (or an authentication strength) together with Require
  password change (or Microsoft's 'riskRemediation' control);
- high SIGN-IN risk (conditions.signInRiskLevels contains 'high') with grant
  Block, or MFA / an authentication strength.

Why it matters: Microsoft Entra ID Protection scores users (leaked
credentials, confirmed compromise, anomalous user activity) and sign-ins
(password spray, anonymous IP, impossible travel, adversary-in-the-middle
token anomalies). Those detections change nothing unless a Conditional
Access policy acts on them. CISA SCuBA MS.AAD.2.1 ("Users detected as high
risk SHALL be blocked") and MS.AAD.2.3 ("Sign-ins detected as high risk
SHALL be blocked"); Microsoft's templates require secure password change
for high user risk and MFA for medium/high sign-in risk. A policy that
also covers medium risk counts as long as 'high' is included.

Licence: risk conditions need Entra ID P2. When the licence inventory was
read (v_entra_tenant_capability.license_status = 'ok') and the tenant has
no P2, nothing is reported (not applicable). When the licence is unknown
(source subscribed_skus not read), the rows are reported and detail says
the licence could not be checked.

Results: fail / high, one row per missing kind, object_guid =
md5('10025:' || client_id || ':user_risk') or ':sign_in_risk'. detail lists
risk policies that exist but don't count (report-only, risk level not
including high, or a grant that neither blocks nor remediates).

Data caveats: needs the CA policy conditions (entra_graph_collector
0.7.0+). If any enabled policy has no conditions object, risk conditions
can't be read and no row is returned. No row when no Entra posture was
collected. The policy's user scope is not evaluated here (exclusions are
plugin 10026's subject).
"""

PLUGIN = {
    "plugin_id": 10025,
    "category": "Hybrid Identity",
    "name": "Risk-Based Conditional Access Policies Missing",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10025",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.2.1",
        "CISA-SCUBA-MS.AAD.2.3",
        "NIST-800-53-SI-4",
        "NIST-800-53-AC-7",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-DE.CM-03",
        "CIS-CSC-8-6.4",
        "ISO-27001-2022-A.8.5",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC6.1",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.2.1, MS.AAD.2.3)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure and enable risk policies",
         "url": "https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies"},
        {"title": "Microsoft: What is risk? (Entra ID Protection)",
         "url": "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks"},
    ],
    "description": (
        "No enabled Conditional Access policy blocks or remediates high user "
        "risk, or blocks / requires MFA for high sign-in risk (one row each). "
        "Identity Protection detections such as leaked credentials, password "
        "spray and token anomalies then have no effect on access (SCuBA "
        "MS.AAD.2.1 / 2.3). Not reported when the tenant is known to lack "
        "Entra ID P2."
    ),
    "remediation": (
        "With Entra ID P2: create a Conditional Access policy for All users "
        "(exclude the emergency-access accounts), All resources, Conditions "
        "-> User risk = High, Grant = Block access (SCuBA) or Require MFA AND "
        "Require password change with Sign-in frequency = Every time; and a "
        "second policy with Conditions -> Sign-in risk = High (and Medium), "
        "Grant = Block access (SCuBA) or Require MFA. Test report-only, then "
        "switch them On. Retire the legacy Identity Protection user-risk and "
        "sign-in-risk policies in favour of these."
    ),
    "base_severity": "high",
    "query": """
        WITH kind(key, label) AS (
            VALUES ('user_risk', 'High user risk'),
                   ('sign_in_risk', 'High sign-in risk')
        ),
        posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        lic AS (
            SELECT c.license_status, c.has_p2
              FROM v_entra_tenant_capability c
             WHERE c.client_id = %(client_id)s
        ),
        raw AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   p->>'state' AS state,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                        THEN p->'grant_controls'->'builtInControls' ELSE '[]'::jsonb END AS builtin,
                   COALESCE(jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object', FALSE) AS has_strength,
                   CASE WHEN jsonb_typeof(p->'conditions'->'userRiskLevels') = 'array'
                        THEN p->'conditions'->'userRiskLevels' ELSE '[]'::jsonb END AS user_risk,
                   CASE WHEN jsonb_typeof(p->'conditions'->'signInRiskLevels') = 'array'
                        THEN p->'conditions'->'signInRiskLevels' ELSE '[]'::jsonb END AS signin_risk
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' IN ('enabled', 'enabledForReportingButNotEnforced')
        ),
        risk_pol AS (
            -- (policy, kind) for every policy that has a risk condition of that kind
            SELECT r.id, r.name, r.state, r.evaluable, 'user_risk' AS key,
                   r.user_risk AS levels,
                   (r.builtin ? 'block' OR r.builtin ? 'riskRemediation'
                    OR ((r.builtin ? 'mfa' OR r.has_strength) AND r.builtin ? 'passwordChange')) AS grant_ok
              FROM raw r
             WHERE jsonb_array_length(r.user_risk) > 0
            UNION ALL
            SELECT r.id, r.name, r.state, r.evaluable, 'sign_in_risk',
                   r.signin_risk,
                   (r.builtin ? 'block' OR r.builtin ? 'mfa' OR r.has_strength)
              FROM raw r
             WHERE jsonb_array_length(r.signin_risk) > 0
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM raw WHERE state = 'enabled' AND NOT evaluable) AS unevaluable,
                   (SELECT license_status FROM lic) AS license_status,
                   (SELECT has_p2 FROM lic) AS has_p2
              FROM posture po
        )
        SELECT
            'fail' AS status,
            md5('10025:' || s.client_id::text || ':' || k.key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            CASE WHEN k.key = 'user_risk'
                 THEN 'No enabled Conditional Access policy blocks or forces remediation of high user risk'
                 ELSE 'No enabled Conditional Access policy blocks or requires MFA for high sign-in risk'
            END AS summary,
            jsonb_build_object(
                'risk_kind', k.label,
                'license_status', COALESCE(s.license_status, 'not collected'),
                'has_p2', CASE WHEN s.license_status = 'ok' THEN s.has_p2 END,
                'license_note', CASE WHEN s.license_status = 'ok' THEN NULL
                                     ELSE 'Licence inventory not read: Entra ID P2 (needed for risk-based '
                                          || 'policies) could not be confirmed, so the check was applied.' END,
                'risk_policies_not_counted',
                    (SELECT jsonb_agg(jsonb_build_object('policy', rp.name, 'id', rp.id, 'state', rp.state,
                                                         'risk_levels', rp.levels,
                                                         'grant_blocks_or_remediates', rp.grant_ok)
                                      ORDER BY rp.name, rp.id)
                       FROM risk_pol rp WHERE rp.key = k.key)
            ) AS detail
        FROM state s
        CROSS JOIN kind k
        WHERE NOT s.unevaluable
          AND NOT (COALESCE(s.license_status, '') = 'ok' AND s.has_p2 IS NOT TRUE)
          AND NOT EXISTS (SELECT 1 FROM risk_pol rp
                           WHERE rp.key = k.key AND rp.state = 'enabled' AND rp.evaluable
                             AND rp.levels ? 'high' AND rp.grant_ok)
    """,
}
