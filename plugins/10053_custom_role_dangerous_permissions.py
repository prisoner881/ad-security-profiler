"""
Plugin 10053: Custom Entra Role Grants Dangerous Permissions

Reports custom directory role definitions (entra_role_definition,
is_built_in = false; schema v42) whose allowed resource actions include an
action that leads to Global Administrator or to the identity of a privileged
user or application:
- microsoft.directory/applications/credentials/update,
  microsoft.directory/servicePrincipals/credentials/update (add a secret or
  certificate to an application and act as it -- MITRE T1098.001);
- microsoft.directory/applications/owners/update,
  microsoft.directory/servicePrincipals/owners/update (make yourself owner,
  then add credentials);
- microsoft.directory/servicePrincipals/appRoleAssignedTo/update (grant
  application permissions such as RoleManagement.ReadWrite.Directory);
- microsoft.directory/roleAssignments/* (assign directory roles);
- microsoft.directory/users/authenticationMethods/* (register or remove MFA
  methods of other users, e.g. a TAP or a phone for an administrator);
- microsoft.directory/users/password/update (reset passwords);
- microsoft.directory/domains/federation/update (federate a domain to an
  attacker IdP -- Golden SAML style persistence, T1484.002);
- microsoft.directory/conditionalAccessPolicies/* (switch off the policies);
- microsoft.directory/groups/members/update (change group membership; Entra
  only lets privileged roles and owners change role-assignable groups, so
  the risk depends on which groups protect what -- reported for review).
Wildcards match: a '*' segment, 'allProperties' in the property position or
'allTasks' / '*' as the verb (e.g. microsoft.directory/applications/
allProperties/allTasks, .../applications/allProperties/update). For the
'/*' families, read-only actions (verb ending in 'read', e.g. standard/read,
restrictedRead) are ignored.

Severity by assignment state (entra_custom_role_assignment, active or
eligible, any scope):
- assigned -> high 'fail';
- not assigned (source custom_role_assignments 'ok', no rows) -> low 'warn'
  (latent: anyone who can assign roles can hand it out);
- unknown (custom_role_assignments not 'ok') -> medium 'warn', noted in
  detail.
Why: custom roles are where escalation paths hide; no built-in-role list
(plugins 10012, 10014, 10018, 10019, 10052) catches them. NIST AC-6(1).

Data caveats: requires_sources ['role_definitions']. Disabled role
definitions (is_enabled false) are still reported, marked in detail.
Assignment scope (directory_scope_id: '/' tenant-wide, '/administrativeUnits/
<id>' or an object) is listed in detail; an AU-scoped assignment is still
reported as assigned.

object_guid: the role definition id.
"""

PLUGIN = {
    "plugin_id": 10053,
    "category": "Hybrid Identity",
    "name": "Custom Entra Role Grants Dangerous Permissions",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10053",
    "requires_sources": ["role_definitions"],
    "framework_tags": [
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-3",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.001",
        "MITRE-ATTCK-T1098.003",
        "MITRE-ATTCK-T1484.002",
    ],
    "references": [
        {"title": "Microsoft: Create and assign a custom role in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/custom-create"},
        {"title": "Microsoft: Microsoft Entra built-in roles (privileged roles and permissions)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
        {"title": "MITRE ATT&CK T1098.001: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A custom Entra role definition includes high-risk actions -- "
        "adding credentials or owners to applications / service principals, "
        "granting app role assignments, managing role assignments, other "
        "users' authentication methods or passwords, domain federation, "
        "Conditional Access policies or group membership -- any of which "
        "can be escalated to Global Administrator. High when the role is "
        "assigned, low when it is not, medium when assignments could not be "
        "read."
    ),
    "remediation": (
        "Entra admin center -> Roles and administrators -> filter Custom "
        "roles -> <role> -> Description / Permissions. Remove the listed "
        "actions unless the role exists precisely to grant them; if it does, "
        "treat it as a Tier-0 role: few holders, PIM-eligible with approval, "
        "phishing-resistant MFA, and assignment scoped to an administrative "
        "unit where possible. Review holders with "
        "Get-MgRoleManagementDirectoryRoleAssignment -Filter "
        "\"roleDefinitionId eq '<id>'\". Delete unused custom roles "
        "(Remove-MgRoleManagementDirectoryRoleDefinition)."
    ),
    "base_severity": "high",
    "query": """
        WITH dangerous (d_entity, d_prop, d_verb) AS (
            VALUES ('applications', 'credentials', 'update'),
                   ('applications', 'owners', 'update'),
                   ('serviceprincipals', 'credentials', 'update'),
                   ('serviceprincipals', 'owners', 'update'),
                   ('serviceprincipals', 'approleassignedto', 'update'),
                   ('roleassignments', '*', '*'),
                   ('users', 'authenticationmethods', '*'),
                   ('users', 'password', 'update'),
                   ('domains', 'federation', 'update'),
                   ('conditionalaccesspolicies', '*', '*'),
                   ('groups', 'members', 'update')
        ),
        assign_src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s AND s.source = 'custom_role_assignments'
                              AND s.status = 'ok') AS ok
        ),
        act AS (
            SELECT rd.role_definition_id, a AS action,
                   string_to_array(lower(btrim(a)), '/') AS seg
              FROM entra_role_definition rd
              CROSS JOIN LATERAL unnest(rd.allowed_actions) a
             WHERE rd.client_id = %(client_id)s
               AND rd.is_built_in IS FALSE
        ),
        parts AS (
            SELECT role_definition_id, action, seg[1] AS ns, COALESCE(seg[2], '') AS e,
                   COALESCE(seg[3], '') AS p,
                   CASE WHEN cardinality(seg) >= 4 THEN seg[cardinality(seg)] ELSE '' END AS v
              FROM act
        ),
        hit AS (
            SELECT DISTINCT pt.role_definition_id, pt.action COLLATE "C" AS action
              FROM parts pt
              JOIN dangerous d ON
                   pt.ns IN ('microsoft.directory', '*')
               AND (pt.ns = '*' OR pt.e = '*' OR pt.e = d.d_entity)
               AND (pt.ns = '*' OR pt.e = '*' OR pt.p IN ('*', 'allproperties')
                    OR d.d_prop = '*' OR pt.p = d.d_prop)
               AND (pt.ns = '*' OR pt.e = '*' OR pt.p = '*' OR pt.v IN ('*', 'alltasks')
                    OR pt.v = d.d_verb
                    OR (d.d_verb = '*' AND pt.v <> '' AND pt.v NOT LIKE '%%read'))
        ),
        per_role AS (
            SELECT h.role_definition_id,
                   jsonb_agg(h.action ORDER BY h.action) AS actions,
                   string_agg(h.action, ', ' ORDER BY h.action) AS action_text,
                   bool_or(lower(h.action) LIKE 'microsoft.directory/groups/%%') AS has_group_members
              FROM hit h
             GROUP BY h.role_definition_id
        ),
        assigned AS (
            SELECT ca.role_definition_id, count(DISTINCT ca.principal_id) AS principal_count,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'principal', COALESCE(ca.principal_upn, ca.principal_display_name, ca.principal_id::text),
                       'principal_type', ca.principal_type,
                       'assignment_type', ca.assignment_type,
                       'scope', ca.directory_scope_id)) AS assignments
              FROM entra_custom_role_assignment ca
             WHERE ca.client_id = %(client_id)s
             GROUP BY ca.role_definition_id
        ),
        v AS (
            SELECT rd.role_definition_id, rd.display_name, rd.is_enabled, pr.actions, pr.action_text,
                   pr.has_group_members, a.principal_count, a.assignments, s.ok AS assign_ok,
                   CASE WHEN a.role_definition_id IS NOT NULL THEN 'assigned'
                        WHEN s.ok THEN 'unassigned' ELSE 'unknown' END AS state
              FROM per_role pr
              JOIN entra_role_definition rd ON rd.client_id = %(client_id)s
                                           AND rd.role_definition_id = pr.role_definition_id
              CROSS JOIN assign_src s
              LEFT JOIN assigned a ON a.role_definition_id = pr.role_definition_id
        )
        SELECT
            CASE v.state WHEN 'assigned' THEN 'fail' ELSE 'warn' END AS status,
            v.role_definition_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE v.state WHEN 'assigned' THEN 'high' WHEN 'unassigned' THEN 'low' ELSE 'medium' END AS fd_severity,
            'Custom role ' || COALESCE(v.display_name, v.role_definition_id::text)
                || CASE v.state WHEN 'assigned' THEN ' (assigned)'
                                WHEN 'unassigned' THEN ' (not assigned)'
                                ELSE ' (assignments not read)' END
                || ' grants dangerous permissions: ' || v.action_text AS summary,
            jsonb_build_object(
                'role', v.display_name,
                'role_definition_id', v.role_definition_id,
                'is_enabled', v.is_enabled,
                'dangerous_actions', v.actions,
                'assignment_state', v.state,
                'assigned_principal_count', v.principal_count,
                'assignments', v.assignments,
                'note', NULLIF(concat_ws(' ',
                    CASE WHEN v.state = 'unknown'
                         THEN 'Custom role assignments could not be read (source custom_role_assignments not ok); assignment state unknown.' END,
                    CASE WHEN v.has_group_members
                         THEN 'groups/members/update: role-assignable groups can only be changed by privileged roles and owners; review which non-role-assignable groups (CA include/exclude, app access) are in scope.' END), '')
            ) AS detail
        FROM v
    """,
}
