"""
Plugin 11031: PIM Role Settings Weakened Since the Previous Run

Change Detection for Microsoft Entra ID. Compares each directory role's
Privileged Identity Management settings (role management policy rules) in
the latest Entra collection with the previous one and reports loosening:

- approval to activate removed (Approval_EndUser_Assignment
  setting.isApprovalRequired true -> false);
- MFA on activation removed (Enablement_EndUser_Assignment enabledRules
  lost 'MultiFactorAuthentication' while no authentication context is
  required);
- justification on activation removed;
- maximum activation duration raised (Expiration_EndUser_Assignment
  maximumDuration);
- permanent eligible or permanent active assignments allowed
  (Expiration_Admin_Eligibility / Expiration_Admin_Assignment
  isExpirationRequired true -> false);
- an administrator notification switched off (a Notification_Admin_* rule
  whose isDefaultRecipientsEnabled went from true to false with no
  additional recipients).

Why: an attacker who reaches Privileged Role Administrator or Global
Administrator loosens PIM before using it -- removing approval and MFA so
eligible accounts they control activate silently, or allowing permanent
assignments -- and plugin 10050 only shows the end state, not that it
changed (MITRE T1484 / T1098.003). Settings changes are rare and should
match a change record.

Data: entra_change_history entity_type 'pim_policy' (content {rules});
from entra_graph_collector 0.9.0 with source pim_policies (Entra ID P2).
Suppressed on the first collection of this entity type. Severity: high for
the highly privileged roles, medium for other roles. One row per role
(object_guid md5('11031:' || client_id || ':' || role template id)).
"""

PLUGIN = {
    "plugin_id": 11031,
    "category": "Change Detection",
    "name": "PIM Role Settings Weakened Since the Previous Run",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "CHANGE-11031",
    "requires_sources": ["pim_policies"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.6",
        "NIST-800-53-CM-3",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1484",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "Microsoft: Configure Microsoft Entra role settings in Privileged Identity Management",
         "url": "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings"},
        {"title": "Microsoft Graph: unifiedRoleManagementPolicyRule resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule"},
        {"title": "MITRE ATT&CK T1098.003: Account Manipulation: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "Reports Privileged Identity Management role settings loosened since the previous "
        "Entra collection: approval, MFA or justification on activation removed, a longer "
        "maximum activation, permanent assignments allowed, or administrator notifications "
        "switched off. High for the highly privileged roles. Suppressed on the first "
        "collection."
    ),
    "remediation": (
        "Confirm the change in the Entra audit log (service PIM, activity 'Update role "
        "setting in PIM') and with the PIM owners. Revert unapproved changes: Identity "
        "Governance > Privileged Identity Management > Microsoft Entra roles > Settings > "
        "the role. Then review activations and new assignments of that role since the change."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'), ('e8611ab8-c189-46e8-94e1-60213ab1f814'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'), ('194ae4cb-b126-40b2-bd5b-6091b380977d'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'),
                   ('db506228-d27e-4b7d-95e5-295956d6615f'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'), ('29232cdf-9323-42fd-ade2-1d097af3e4de'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'), ('fe930be7-5e62-47db-91af-98c3a49a38b1'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5')
        ),
        b AS (
            SELECT bl.client_id, bl.last_run_at
              FROM entra_change_baseline bl
             WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'pim_policy'
               AND bl.first_run_at < bl.last_run_at
        ),
        chg AS (
            SELECT nv.entity_key, nv.entity_label, nv.content AS new_c, ov.content AS old_c
              FROM b
              JOIN entra_change_history nv
                ON nv.client_id = b.client_id AND nv.entity_type = 'pim_policy'
               AND nv.valid_from = b.last_run_at AND nv.valid_to IS NULL
              JOIN entra_change_history ov
                ON ov.client_id = b.client_id AND ov.entity_type = 'pim_policy'
               AND ov.entity_key = nv.entity_key AND ov.valid_to = b.last_run_at
        ),
        side AS (
            SELECT c.entity_key, c.entity_label, s.which, s.content,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'Approval_EndUser_Assignment' LIMIT 1) AS r_approval,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'Enablement_EndUser_Assignment' LIMIT 1) AS r_enable,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'AuthenticationContext_EndUser_Assignment' LIMIT 1) AS r_authctx,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'Expiration_EndUser_Assignment' LIMIT 1) AS r_exp_user,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'Expiration_Admin_Eligibility' LIMIT 1) AS r_exp_elig,
                   (SELECT r FROM jsonb_array_elements(CASE WHEN jsonb_typeof(s.content->'rules') = 'array'
                                                            THEN s.content->'rules' ELSE '[]'::jsonb END) r
                     WHERE r->>'id' = 'Expiration_Admin_Assignment' LIMIT 1) AS r_exp_assign,
                   (SELECT jsonb_object_agg(r->>'id', r) FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(s.content->'rules') = 'array' THEN s.content->'rules'
                             ELSE '[]'::jsonb END) r
                     WHERE r->>'id' LIKE 'Notification_Admin_%%') AS r_notify
              FROM chg c
              CROSS JOIN LATERAL (VALUES ('new', c.new_c), ('old', c.old_c)) s(which, content)
        ),
        parsed AS (
            SELECT s.*,
                   CASE WHEN jsonb_typeof(s.r_enable->'enabledRules') = 'array'
                        THEN s.r_enable->'enabledRules' END AS enabled_rules,
                   (SELECT COALESCE(m[1]::numeric, 0) * 604800 + COALESCE(m[2]::numeric, 0) * 86400
                           + COALESCE(m[3]::numeric, 0) * 3600 + COALESCE(m[4]::numeric, 0) * 60
                           + COALESCE(m[5]::numeric, 0)
                      FROM regexp_match(upper(btrim(s.r_exp_user->>'maximumDuration')),
                           '^P(?:([0-9]+)W)?(?:([0-9]+)D)?(?:T(?:([0-9]+)H)?(?:([0-9]+)M)?(?:([0-9]+(?:[.][0-9]+)?)S)?)?$') m
                     WHERE m IS NOT NULL) AS max_seconds
              FROM side s
        ),
        pair AS (
            SELECT n.entity_key, n.entity_label, n, o
              FROM parsed n
              JOIN parsed o ON o.entity_key = n.entity_key AND o.which = 'old'
             WHERE n.which = 'new'
        ),
        loosened AS (
            SELECT p.entity_key, p.entity_label,
                   array_remove(ARRAY[
                       CASE WHEN (p.o).r_approval->'setting'->'isApprovalRequired' = 'true'::jsonb
                                 AND (p.n).r_approval->'setting'->'isApprovalRequired' = 'false'::jsonb
                            THEN 'approval to activate removed' END,
                       CASE WHEN (p.o).enabled_rules ? 'MultiFactorAuthentication'
                                 AND (p.n).enabled_rules IS NOT NULL
                                 AND NOT (p.n).enabled_rules ? 'MultiFactorAuthentication'
                                 AND COALESCE((p.n).r_authctx->'isEnabled', 'false'::jsonb) <> 'true'::jsonb
                            THEN 'MFA on activation removed' END,
                       CASE WHEN (p.o).enabled_rules ? 'Justification'
                                 AND (p.n).enabled_rules IS NOT NULL
                                 AND NOT (p.n).enabled_rules ? 'Justification'
                            THEN 'justification on activation removed' END,
                       CASE WHEN (p.n).max_seconds > (p.o).max_seconds
                            THEN 'maximum activation duration raised from ' || ((p.o).r_exp_user->>'maximumDuration')
                                 || ' to ' || ((p.n).r_exp_user->>'maximumDuration') END,
                       CASE WHEN (p.o).r_exp_elig->'isExpirationRequired' = 'true'::jsonb
                                 AND (p.n).r_exp_elig->'isExpirationRequired' = 'false'::jsonb
                            THEN 'permanent eligible assignments now allowed' END,
                       CASE WHEN (p.o).r_exp_assign->'isExpirationRequired' = 'true'::jsonb
                                 AND (p.n).r_exp_assign->'isExpirationRequired' = 'false'::jsonb
                            THEN 'permanent active assignments now allowed' END,
                       (SELECT 'administrator notification switched off ('
                               || string_agg(k, ', ' ORDER BY k) || ')'
                          FROM jsonb_object_keys(COALESCE((p.n).r_notify, '{}'::jsonb)) k
                         WHERE (p.o).r_notify->k->'isDefaultRecipientsEnabled' = 'true'::jsonb
                           AND (p.n).r_notify->k->'isDefaultRecipientsEnabled' = 'false'::jsonb
                           AND COALESCE(jsonb_array_length(CASE WHEN jsonb_typeof((p.n).r_notify->k->'notificationRecipients') = 'array'
                                                                THEN (p.n).r_notify->k->'notificationRecipients' END), 0) = 0)
                   ], NULL) AS items,
                   (p.n).content->>'role_display_name' AS role_name
              FROM pair p
        )
        SELECT
            'fail' AS status,
            md5('11031:' || %(client_id)s::text || ':' || l.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN EXISTS (SELECT 1 FROM tier0 t WHERE t.role_template_id = l.entity_key) THEN 'high'
                 ELSE 'medium' END AS fd_severity,
            'PIM settings for ' || COALESCE(l.role_name, l.entity_label, l.entity_key)
                || ' loosened since the previous Entra collection: ' || array_to_string(l.items, '; ') AS summary,
            jsonb_build_object(
                'role', COALESCE(l.role_name, l.entity_label),
                'role_template_id', l.entity_key,
                'changes', to_jsonb(l.items),
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM loosened l
        WHERE cardinality(l.items) > 0
    """,
}
