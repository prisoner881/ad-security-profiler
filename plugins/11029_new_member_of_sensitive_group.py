"""
Plugin 11029: New Member of a Role-Assignable, CA-Exclusion or Privileged App-Role Group

Change Detection for Microsoft Entra ID. Reports members (transitive) added,
in the latest Entra collection, to a sensitive group whose sensitive_reasons
include 'ca_exclude' (excluded from a Conditional Access policy that is not
disabled), 'role_assignable' (isAssignableToRole) or 'app_role' (assigned an
app role on a service principal that holds a privileged permission or
directory role) -- and that does NOT itself hold a directory role
('holds_role'), because new members of role-holding groups are already
reported by plugin 11020 as new role assignments.

Why: adding an account to a Conditional Access exclusion group switches MFA
or blocking off for it; adding it to a role-assignable group is one
role-assignment away from (or a PIM-for-Groups activation into) a privileged
role; adding it to an app-role group grants the privileged application
access. Guests and on-premises-synced accounts added this way extend the
attack surface beyond the tenant (MITRE ATT&CK T1098 Account Manipulation,
T1098.003 Additional Cloud Roles).

Data: entra_change_history entity_type 'group_member' (key <group id>:<member
id>; content {group_id, group_display_name, group_sensitive_reasons,
member_id, member_type, member_display_name, member_upn, member_user_type,
on_premises_sync_enabled}) and entra_change_baseline. The reasons recorded
in the version itself are used (falling back to the current entra_group
row). Only NEW memberships (no earlier version of the key) are reported.
Suppressed on the first collection; findings stay open until the next Entra
collection.

Severity: high for ca_exclude or role_assignable groups; medium for app_role
only. One row per (group, member) (object_guid = md5('11029:' || client_id ||
':' || key)).
"""

PLUGIN = {
    "plugin_id": 11029,
    "category": "Change Detection",
    "name": "New Member of a Role-Assignable, CA-Exclusion or Privileged App-Role Group",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11029",
    "requires_sources": ["groups"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "Microsoft: Use Microsoft Entra groups to manage role assignments",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept"},
        {"title": "Microsoft: Conditional Access -- users and groups (exclusions)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups"},
        {"title": "MITRE ATT&CK T1098.003: Account Manipulation: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "Reports accounts added since the previous Entra collection to groups excluded from "
        "Conditional Access, role-assignable groups (high) or groups granted a privileged "
        "app role (medium), when the group does not itself hold a directory role (those "
        "additions are reported by plugin 11020). Adding a member to an exclusion group "
        "switches MFA off for it. Suppressed on the first Entra collection."
    ),
    "remediation": (
        "Confirm the membership against an approved request (Entra audit log: 'Add member to "
        "group'; for synced groups, the AD security log events 4728/4732/4756). Remove "
        "unapproved members, review the member's sign-ins since, and govern these groups with "
        "access reviews or PIM for Groups; keep CA exclusion groups to break-glass accounts "
        "and cloud-only (see plugin 10112)."
    ),
    "base_severity": "high",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'group_member'
              AND bl.first_run_at < bl.last_run_at
        ),
        new_member AS (
            SELECT h.entity_key, h.entity_label, h.content,
                   CASE WHEN h.content->>'group_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        THEN (h.content->>'group_id')::uuid END AS group_id
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'group_member'
              AND h.valid_from = b.last_run_at
              AND h.valid_to IS NULL
              AND NOT EXISTS (SELECT 1 FROM entra_change_history e
                              WHERE e.client_id = h.client_id AND e.entity_type = h.entity_type
                                AND e.entity_key = h.entity_key AND e.valid_from < b.last_run_at)
        ),
        reasons AS (
            SELECT n.*,
                   COALESCE(
                       CASE WHEN jsonb_typeof(n.content->'group_sensitive_reasons') = 'array'
                            THEN ARRAY(SELECT jsonb_array_elements_text(n.content->'group_sensitive_reasons')) END,
                       g.sensitive_reasons, '{}'::text[]) AS rs,
                   g.display_name AS current_group_name
            FROM new_member n
            LEFT JOIN entra_group g
              ON g.client_id = %(client_id)s AND g.entra_object_id = n.group_id
        ),
        f AS (
            SELECT r.*,
                   ARRAY(SELECT x FROM unnest(r.rs) x
                         WHERE x IN ('ca_exclude', 'role_assignable', 'app_role') ORDER BY x) AS hit
            FROM reasons r
            WHERE NOT ('holds_role' = ANY (r.rs))
        )
        SELECT
            CASE WHEN f.hit && ARRAY['ca_exclude', 'role_assignable'] THEN 'fail' ELSE 'warn' END AS status,
            md5('11029:' || %(client_id)s::text || ':' || f.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN f.hit && ARRAY['ca_exclude', 'role_assignable'] THEN 'high' ELSE 'medium' END AS fd_severity,
            'New member '
                || CASE f.content->>'member_type'
                       WHEN '#microsoft.graph.user' THEN 'user '
                       WHEN '#microsoft.graph.group' THEN 'group '
                       WHEN '#microsoft.graph.servicePrincipal' THEN 'service principal '
                       WHEN '#microsoft.graph.device' THEN 'device '
                       ELSE '' END
                || '"' || COALESCE(f.content->>'member_upn', f.content->>'member_display_name',
                                   f.content->>'member_id', '?') || '"'
                || CASE WHEN f.content->>'member_user_type' = 'Guest' THEN ' (guest)' ELSE '' END
                || CASE WHEN f.content->>'on_premises_sync_enabled' = 'true' THEN ' (synced from AD)' ELSE '' END
                || ' added to group "'
                || COALESCE(f.content->>'group_display_name', f.current_group_name, f.entity_label,
                            f.content->>'group_id', '?')
                || '" (' || array_to_string(f.hit, ', ') || ')'
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'group_id', f.content->>'group_id',
                'group_display_name', COALESCE(f.content->>'group_display_name', f.current_group_name),
                'group_sensitive_reasons', to_jsonb(f.rs),
                'member_id', f.content->>'member_id',
                'member_type', f.content->>'member_type',
                'member_display_name', f.content->>'member_display_name',
                'member_upn', f.content->>'member_upn',
                'member_user_type', f.content->>'member_user_type',
                'on_premises_sync_enabled', f.content->'on_premises_sync_enabled',
                'detected_at', (SELECT last_run_at FROM b),
                'related_plugins', jsonb_build_array(11020, 10112)
            ) AS detail
        FROM f
        WHERE cardinality(f.hit) > 0
    """,
}
