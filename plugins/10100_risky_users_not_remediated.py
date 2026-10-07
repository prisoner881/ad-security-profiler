"""
Plugin 10100: Risky Users Not Remediated

Reads Identity Protection risky users (entra_risky_user, source
risky_users: identityProtection/riskyUsers with riskState 'atRisk' or
'confirmedCompromised'; IdentityRiskyUser.Read.All and Entra ID P2) and
reports users whose risk nobody has remediated or dismissed:

- riskState 'confirmedCompromised' -> critical;
- riskLevel 'high' -> critical when the user holds a highly privileged
  (Tier 0) Entra role (active or PIM-eligible, directly or via a group),
  otherwise high;
- riskLevel 'medium' -> high when privileged, otherwise medium.
Low-risk users are not reported. Users whose risk was remediated or
dismissed are not in the table.

Why: CISA SCuBA MS.AAD.2.1 (users detected as high risk SHALL be blocked)
and MS.AAD.2.2 (administrators SHOULD be notified). An open user risk is a
fact Microsoft has already established -- leaked credentials, anomalous
tokens, impossible travel -- that nobody has acted on. For a user synced
from AD (detail.synced) the on-premises account is affected too; plugin
10101 joins leaked-credential detections to on-premises privilege.

Licence: the source needs Entra ID P2; without it the source is not 'ok'
and adaudit reports NOT ASSESSED.

One finding per user (object_guid = the user's Entra object id).
"""

PLUGIN = {
    "plugin_id": 10100,
    "category": "Hybrid Identity",
    "name": "Risky Users Not Remediated",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10100",
    "requires_sources": ["risky_users"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.2.1",
        "CISA-SCUBA-MS.AAD.2.2",
        "NIST-800-53-SI-4",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-DE.CM-09",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.2.1, 2.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Remediate risks and unblock users in Microsoft Entra ID Protection",
         "url": "https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock"},
        {"title": "Microsoft Graph: riskyUser resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/riskyuser"},
    ],
    "description": (
        "Identity Protection marks a user as at risk (high or medium) or "
        "confirmed compromised, and the risk has not been remediated or "
        "dismissed. Critical when confirmed compromised or high risk on a "
        "user holding a highly privileged Entra role; high for other "
        "high-risk users and privileged medium-risk users; medium "
        "otherwise. SCuBA MS.AAD.2.1/2.2. One finding per user."
    ),
    "remediation": (
        "Investigate each user's risk detections (Entra admin center -> "
        "Protection -> Identity Protection -> Risky users). For a real "
        "compromise: reset the password (on-premises too for synced "
        "users), revoke sessions (Revoke-MgUserSignInSession), review "
        "MFA methods and app consents the attacker may have added, then "
        "confirm compromised or remediate; dismiss only false positives "
        "(Invoke-MgDismissRiskyUser). Enforce a user-risk Conditional "
        "Access policy that blocks high-risk users or requires a secure "
        "password change, and send risky-user alerts to the SOC."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0_role(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        priv AS (
            SELECT rm.member_id,
                   string_agg(DISTINCT rm.role_display_name, ', ' ORDER BY rm.role_display_name) AS roles
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
             GROUP BY rm.member_id
        ),
        ru AS (
            SELECT r.*
              FROM entra_risky_user r
             WHERE r.client_id = %(client_id)s
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = r.client_id
                              AND s.source = 'risky_users' AND s.status = 'ok')
               AND (r.risk_state = 'confirmedCompromised'
                    OR (r.risk_state = 'atRisk' AND r.risk_level IN ('high', 'medium')))
        ),
        judged AS (
            SELECT r.*, p.roles,
                   CASE WHEN r.risk_state = 'confirmedCompromised' THEN 'critical'
                        WHEN r.risk_level = 'high' AND p.member_id IS NOT NULL THEN 'critical'
                        WHEN r.risk_level = 'high' THEN 'high'
                        WHEN p.member_id IS NOT NULL THEN 'high'
                        ELSE 'medium' END AS sev
              FROM ru r
              LEFT JOIN priv p ON p.member_id = r.entra_object_id
        )
        SELECT
            'fail' AS status,
            j.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            j.sev AS fd_severity,
            'User ' || COALESCE(eu.user_principal_name, j.user_principal_name, j.entra_object_id::text)
                || CASE WHEN j.risk_state = 'confirmedCompromised' THEN ' is confirmed compromised'
                        ELSE ' is at ' || j.risk_level || ' user risk' END
                || ' and has not been remediated'
                || CASE WHEN j.roles IS NOT NULL
                        THEN '; holds highly privileged Entra roles (' || j.roles || ')' ELSE '' END
                AS summary,
            jsonb_build_object(
                'entra_object_id', j.entra_object_id,
                'user_principal_name', COALESCE(eu.user_principal_name, j.user_principal_name),
                'risk_level', j.risk_level,
                'risk_state', j.risk_state,
                'risk_detail', j.risk_detail,
                'risk_last_updated_at', j.risk_last_updated_at,
                'privileged_entra_roles', j.roles,
                'account_enabled', eu.account_enabled,
                'user_type', eu.user_type,
                'synced', (eu.on_premises_sync_enabled IS TRUE),
                'on_prem_object_guid', eu.on_prem_object_guid,
                'related_plugins', jsonb_build_array(10101)
            ) AS detail
        FROM judged j
        LEFT JOIN entra_user eu ON eu.client_id = j.client_id AND eu.entra_object_id = j.entra_object_id
    """,
}
