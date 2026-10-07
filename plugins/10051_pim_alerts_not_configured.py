"""
Plugin 10051: PIM Assignment and Activation Alerts Not Configured

Reads the notification rules of the PIM role settings of every highly
privileged directory role (entra_role_management_policy, schema v42) and
reports the roles whose assignment or activation alerts reach nobody beyond
PIM's default recipients.

Rules checked, per role:
- Notification_Admin_Admin_Assignment ("send notifications when members are
  assigned as active") and Notification_Admin_Admin_Eligibility ("... as
  eligible"): the alert on new privileged assignments (CISA SCuBA
  MS.AAD.7.7: eligible and active highly privileged role assignments SHALL
  trigger an alert);
- Notification_Admin_EndUser_Assignment ("send notifications when eligible
  members activate"): the activation alert (SCuBA MS.AAD.7.8 for Global
  Administrator, MS.AAD.7.9 for the other highly privileged roles).
A rule is flagged when its notificationRecipients list is empty (only the
default recipients -- typically the role's Global/Privileged Role
Administrators themselves, whom an attacker holding the role can ignore --
are notified, and nobody at all when isDefaultRecipientsEnabled is false) or
its notificationLevel is 'None'. SCuBA expects these alerts to go to a
monitored mailbox / the security operations team.

Severity: medium 'warn' for Global Administrator, low 'warn' for the other
highly privileged roles (Privileged Role, Privileged Authentication,
Security, Hybrid Identity, Application, Cloud Application, Exchange,
SharePoint, User, Conditional Access, Authentication and Intune
Administrator). One finding per role listing the flagged alerts.

Data caveats: PIM role settings need Entra ID P2; requires_sources
['pim_policies']. A notification rule missing from a role's policy is
treated as unknown and not flagged. Roles with no PIM policy row are not
reported.

object_guid: md5('10051:' || client_id || ':' || role template id).
"""

PLUGIN = {
    "plugin_id": 10051,
    "category": "Hybrid Identity",
    "name": "PIM Assignment and Activation Alerts Not Configured",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10051",
    "requires_sources": ["pim_policies"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.7",
        "CISA-SCUBA-MS.AAD.7.8",
        "CISA-SCUBA-MS.AAD.7.9",
        "NIST-800-53-AU-6",
        "NIST-800-53-AC-2(4)",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.7-7.9)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure Microsoft Entra role settings in Privileged Identity Management",
         "url": "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings"},
        {"title": "Microsoft Graph: unifiedRoleManagementPolicyNotificationRule resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicynotificationrule"},
    ],
    "description": (
        "PIM alerts for a highly privileged Entra role -- new active or "
        "eligible assignments (SCuBA MS.AAD.7.7) and role activation "
        "(MS.AAD.7.8 for Global Administrator, 7.9 for others) -- are sent "
        "to no additional recipient, so privilege use is not seen by the "
        "security team. Medium for Global Administrator, low for the other "
        "highly privileged roles. Needs the PIM role settings (Entra ID P2)."
    ),
    "remediation": (
        "Entra admin center -> Identity governance -> Privileged Identity "
        "Management -> Microsoft Entra roles -> Settings -> <role> -> Edit -> "
        "Notification: for 'Send notifications when members are assigned as "
        "eligible / active' and 'Send notifications when eligible members "
        "activate this role', add the security operations mailbox (or SIEM "
        "ingestion address) under 'Additional recipients' of the 'Role "
        "assignment alert' / 'Role activation alert'. Graph: update the "
        "Notification_Admin_Admin_Assignment, Notification_Admin_Admin_"
        "Eligibility and Notification_Admin_EndUser_Assignment rules' "
        "notificationRecipients."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0 (template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        alert (rule_id, label, ord) AS (
            VALUES ('Notification_Admin_Admin_Assignment', 'active assignment alert', 1),
                   ('Notification_Admin_Admin_Eligibility', 'eligible assignment alert', 2),
                   ('Notification_Admin_EndUser_Assignment', 'activation alert', 3)
        ),
        rules AS (
            SELECT p.client_id, p.role_template_id, p.policy_id, t.role_name, a.label, a.ord, r
              FROM entra_role_management_policy p
              JOIN tier0 t ON t.template_id = p.role_template_id
              CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(p.rules) = 'array'
                                                           THEN p.rules ELSE '[]'::jsonb END) r
              JOIN alert a ON a.rule_id = r->>'id'
             WHERE p.client_id = %(client_id)s
               AND jsonb_typeof(r) = 'object'
        ),
        flagged AS (
            SELECT DISTINCT ON (client_id, role_template_id, ord)
                   client_id, role_template_id, policy_id, role_name, label, ord,
                   r->'isDefaultRecipientsEnabled' AS default_recipients_enabled,
                   r->>'notificationLevel' AS notification_level
              FROM rules
             WHERE COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof(r->'notificationRecipients') = 'array'
                                                    THEN r->'notificationRecipients' END), 0) = 0
                OR r->>'notificationLevel' = 'None'
             ORDER BY client_id, role_template_id, ord
        ),
        agg AS (
            SELECT client_id, role_template_id, min(policy_id) AS policy_id, min(role_name) AS role_name,
                   string_agg(label, ', ' ORDER BY ord) AS labels,
                   jsonb_agg(jsonb_build_object('alert', label,
                                                'default_recipients_enabled', default_recipients_enabled,
                                                'notification_level', notification_level)
                             ORDER BY ord) AS alerts
              FROM flagged
             GROUP BY client_id, role_template_id
        )
        SELECT
            'warn' AS status,
            md5('10051:' || a.client_id::text || ':' || a.role_template_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.role_template_id = '62e90394-69f5-4237-9190-012177145e10' THEN 'medium' ELSE 'low' END
                AS fd_severity,
            'PIM alerts for ' || a.role_name || ' are not sent to any additional recipient: ' || a.labels AS summary,
            jsonb_build_object(
                'role', a.role_name,
                'role_template_id', a.role_template_id,
                'policy_id', a.policy_id,
                'alerts_without_recipients', a.alerts,
                'scuba_activation_control',
                    CASE WHEN a.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
                         THEN 'MS.AAD.7.8' ELSE 'MS.AAD.7.9' END
            ) AS detail
        FROM agg a
    """,
}
