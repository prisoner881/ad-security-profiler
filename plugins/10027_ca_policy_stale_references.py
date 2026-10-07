"""
Plugin 10027: Conditional Access Policy References Deleted Objects

Reports each Conditional Access policy that is not disabled (enabled or
report-only) whose user conditions name objects that no longer exist:
- user ids in includeUsers / excludeUsers that are not in entra_user
  (the keywords 'All', 'None' and 'GuestsOrExternalUsers' are ignored);
- group ids in includeGroups / excludeGroups that are not in entra_group
  (only when source 'groups' is 'ok');
- role template ids in includeRoles / excludeRoles that match no role
  definition (template_id or id) in entra_role_definition (only when source
  'role_definitions' is 'ok').

Why it matters: Conditional Access keeps the ids of deleted objects. An
include list that points only at a deleted group silently protects nobody,
while the policy still looks configured; a stale id on an exclusion list is
a sign of unmanaged exceptions (and a recreated object never inherits the
old id, so the intent is lost either way). Good configuration hygiene
(NIST CM-6) and a common finding in Conditional Access reviews.

Severity: warn / medium when any stale id is on an include list (coverage
may be silently missing); warn / low when they are only on exclude lists.
One row per policy, object_guid = the policy id (md5('10027:' ||
client_id || ':' || id) if the id is not a uuid).

Data caveats: user ids are only checked when entra_user has rows for the
client (the user inventory is part of every Entra collection). Group and
role checks are skipped -- not guessed -- when their source was not read;
detail says which kinds were checked. Policies without a conditions object
(older collector) are skipped. No row when no Entra posture was collected.
"""

PLUGIN = {
    "plugin_id": 10027,
    "category": "Hybrid Identity",
    "name": "Conditional Access Policy References Deleted Objects",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10027",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
    ],
    "references": [
        {"title": "Microsoft: Conditional Access users and groups (include / exclude)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups"},
        {"title": "Microsoft Graph: conditionalAccessUsers resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers"},
    ],
    "description": (
        "Conditional Access policies (enabled or report-only) whose include "
        "or exclude lists name users, groups or directory roles that no "
        "longer exist. A stale include can leave the policy protecting "
        "nobody without any visible sign (medium); stale exclusions point to "
        "unmanaged exceptions (low)."
    ),
    "remediation": (
        "Open each reported policy in the Entra admin center (Protection -> "
        "Conditional Access); deleted objects show as unknown ids under "
        "Users -> Include / Exclude. Remove them, and re-target the policy at "
        "the intended current users, groups or roles. Check that the policy "
        "still applies to the population it was meant to protect (What If "
        "tool). Microsoft Graph: PATCH /identity/conditionalAccess/policies/{id} "
        "with the cleaned conditions.users lists."
    ),
    "base_severity": "medium",
    "query": """
        WITH posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        flags AS (
            SELECT EXISTS (SELECT 1 FROM entra_user u WHERE u.client_id = %(client_id)s) AS users_present,
                   EXISTS (SELECT 1 FROM entra_collection_status s WHERE s.client_id = %(client_id)s
                             AND s.source = 'groups' AND s.status = 'ok') AS groups_ok,
                   EXISTS (SELECT 1 FROM entra_collection_status s WHERE s.client_id = %(client_id)s
                             AND s.source = 'role_definitions' AND s.status = 'ok') AS roles_ok
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   p->>'state' AS state,
                   p->'conditions'->'users' AS cu
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE COALESCE(p->>'state', '') <> 'disabled'
               AND jsonb_typeof(p->'conditions'->'users') = 'object'
        ),
        ref AS (
            SELECT pl.id, pl.name, pl.state, l.side, l.kind, lower(v) AS v
              FROM pol pl
              CROSS JOIN LATERAL (VALUES ('include', 'user', 'includeUsers'), ('exclude', 'user', 'excludeUsers'),
                                         ('include', 'group', 'includeGroups'), ('exclude', 'group', 'excludeGroups'),
                                         ('include', 'role', 'includeRoles'), ('exclude', 'role', 'excludeRoles'))
                           AS l(side, kind, key)
              CROSS JOIN LATERAL jsonb_array_elements_text(
                  CASE WHEN jsonb_typeof(pl.cu->l.key) = 'array' THEN pl.cu->l.key ELSE '[]'::jsonb END) v
        ),
        stale AS (
            SELECT r.*
              FROM ref r
              CROSS JOIN flags f
             WHERE (r.kind = 'user' AND f.users_present
                    AND r.v NOT IN ('all', 'none', 'guestsorexternalusers')
                    AND NOT EXISTS (SELECT 1 FROM entra_user u
                                     WHERE u.client_id = %(client_id)s AND u.entra_object_id::text = r.v))
                OR (r.kind = 'group' AND f.groups_ok
                    AND NOT EXISTS (SELECT 1 FROM entra_group g
                                     WHERE g.client_id = %(client_id)s AND g.entra_object_id::text = r.v))
                OR (r.kind = 'role' AND f.roles_ok
                    AND NOT EXISTS (SELECT 1 FROM entra_role_definition d
                                     WHERE d.client_id = %(client_id)s
                                       AND (d.template_id::text = r.v OR d.role_definition_id::text = r.v)))
        ),
        agg AS (
            SELECT s.id, s.name, s.state,
                   bool_or(s.side = 'include') AS on_include,
                   jsonb_object_agg(s.side || '_' || s.kind || 's', s.vals ORDER BY s.side, s.kind) AS stale_ids
              FROM (SELECT id, name, state, side, kind, jsonb_agg(DISTINCT v ORDER BY v) AS vals
                      FROM stale GROUP BY id, name, state, side, kind) s
             GROUP BY s.id, s.name, s.state
        )
        SELECT
            'warn' AS status,
            CASE WHEN a.id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN a.id::uuid
                 ELSE md5('10027:' || %(client_id)s::text || ':' || COALESCE(a.id, a.name))::uuid END AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.on_include THEN 'medium' ELSE 'low' END AS fd_severity,
            'Conditional Access policy "' || COALESCE(a.name, '') || '" references deleted '
                || CASE WHEN a.on_include THEN 'objects in its include conditions'
                        ELSE 'objects in its exclusions' END AS summary,
            jsonb_build_object(
                'policy_id', a.id,
                'policy_name', a.name,
                'state', a.state,
                'stale_ids', a.stale_ids,
                'checked', jsonb_build_object('users', f.users_present, 'groups', f.groups_ok,
                                              'roles', f.roles_ok)
            ) AS detail
        FROM agg a
        CROSS JOIN flags f
    """,
}
