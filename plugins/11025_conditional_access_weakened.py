"""
Plugin 11025: Conditional Access Policy Weakened, Changed or Deleted; Security Defaults Turned Off

Change Detection for Microsoft Entra ID. Reports Conditional Access policies
created, modified or deleted in the latest Entra collection, and Security
Defaults being turned off.

Why: attackers -- and careless administrators -- weaken Conditional Access
before acting: they switch a policy to report-only or off, add their account
or group to an exclusion, narrow who or what the policy applies to, or drop
the MFA / block control (MITRE ATT&CK T1484.002 Domain or Tenant Policy
Modification; T1556 Modify Authentication Process). Each such change silently
removes a control the rest of this assessment relies on.

Data: entra_change_history entity_type 'ca_policy' (key = policy id,
content = the stored entra_security_posture.ca_policies element) and
entity_type 'tenant_policy' key 'security_defaults' (content {enabled}),
with entra_change_baseline for each entity type. Suppressed per entity
type on its first collection; findings stay open until the next Entra
collection.

Severity high when:
  * an enabled policy was deleted, disabled or switched to report-only;
  * a policy enabled before or after the change gained exclusions
    (excludeUsers, excludeGroups, excludeRoles, excludeApplications,
    excludeLocations, excludePlatforms, excludeGuestsOrExternalUsers);
  * such a policy was loosened: entries removed from includeUsers,
    includeGroups, includeRoles, includeApplications, includeUserActions,
    clientAppTypes, includeLocations or includePlatforms; a grant control
    removed from builtInControls; the authentication strength removed; or
    the grant operator changed from AND to OR;
  * Security Defaults changed from enabled to disabled.
Severity medium for every other CA change (new policy, deleted policy that
was not enabled, other edits). detail lists the changed top-level keys and
condition keys, the exclusions added and the inclusions / controls removed.
One row per policy (object_guid = the policy id) plus one for Security
Defaults (md5('11025:' || client_id || ':security_defaults')).
"""

PLUGIN = {
    "plugin_id": 11025,
    "category": "Change Detection",
    "name": "Conditional Access Policy Weakened, Changed or Deleted; Security Defaults Turned Off",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11025",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32",
        "SOC2-CC7.2", "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.002", "MITRE-ATTCK-T1556",
    ],
    "references": [
        {"title": "Microsoft: Conditional Access deployment and policy change monitoring",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access"},
        {"title": "Microsoft: Security defaults in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults"},
        {"title": "MITRE ATT&CK T1484.002: Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
    ],
    "description": (
        "Reports Conditional Access changes since the previous Entra collection. High when an "
        "enabled policy is deleted, disabled or switched to report-only, when an active "
        "policy gains exclusions or loses targets or grant controls (MFA, block, compliant "
        "device, authentication strength, AND operator), or when Security Defaults is turned "
        "off; medium for other policy changes and new policies. Suppressed on the first "
        "Entra collection."
    ),
    "remediation": (
        "Confirm the change in the Entra audit log (service 'Conditional Access', activities "
        "'Update conditional access policy', 'Delete conditional access policy'; 'Update "
        "policy' for Security Defaults) and the CA policy's version history. Revert "
        "unapproved changes (restore from the policy's previous version or from a backup "
        "exported with Get-MgIdentityConditionalAccessPolicy), and review sign-ins that the "
        "weakened policy no longer covered. Limit Conditional Access Administrator / Security "
        "Administrator membership and alert on CA changes in the SIEM."
    ),
    "base_severity": "high",
    "query": """
        WITH bc AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'ca_policy'
              AND bl.first_run_at < bl.last_run_at
        ),
        bt AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'tenant_policy'
              AND bl.first_run_at < bl.last_run_at
        ),
        kc AS (
            SELECT DISTINCT h.entity_key
            FROM entra_change_history h
            JOIN bc ON bc.client_id = h.client_id
            WHERE h.entity_type = 'ca_policy'
              AND (h.valid_from = bc.last_run_at OR h.valid_to = bc.last_run_at)
        ),
        chg AS (
            SELECT kc.entity_key,
                   COALESCE(nv.content->>'display_name', ov.content->>'display_name',
                            nv.entity_label, ov.entity_label, kc.entity_key) AS label,
                   nv.content AS new_c, ov.content AS old_c,
                   CASE WHEN nv.content IS NOT NULL AND ov.content IS NULL THEN 'new'
                        WHEN nv.content IS NOT NULL THEN 'modified'
                        ELSE 'removed' END AS kind,
                   ov.content->>'state' AS old_state,
                   nv.content->>'state' AS new_state
            FROM kc
            CROSS JOIN bc
            LEFT JOIN entra_change_history nv
              ON nv.client_id = bc.client_id AND nv.entity_type = 'ca_policy'
             AND nv.entity_key = kc.entity_key AND nv.valid_from = bc.last_run_at AND nv.valid_to IS NULL
            LEFT JOIN entra_change_history ov
              ON ov.client_id = bc.client_id AND ov.entity_type = 'ca_policy'
             AND ov.entity_key = kc.entity_key AND ov.valid_to = bc.last_run_at
        ),
        excl_path (pth) AS (
            VALUES ('{conditions,users,excludeUsers}'::text[]), ('{conditions,users,excludeGroups}'),
                   ('{conditions,users,excludeRoles}'), ('{conditions,applications,excludeApplications}'),
                   ('{conditions,locations,excludeLocations}'), ('{conditions,platforms,excludePlatforms}')
        ),
        incl_path (pth) AS (
            VALUES ('{conditions,users,includeUsers}'::text[]), ('{conditions,users,includeGroups}'),
                   ('{conditions,users,includeRoles}'), ('{conditions,applications,includeApplications}'),
                   ('{conditions,applications,includeUserActions}'), ('{conditions,clientAppTypes}'),
                   ('{conditions,locations,includeLocations}'), ('{conditions,platforms,includePlatforms}'),
                   ('{grant_controls,builtInControls}')
        ),
        eval AS (
            SELECT c.*,
                   (SELECT jsonb_object_agg(z.pth_name, z.added ORDER BY z.pth_name) FROM (
                        SELECT array_to_string(p.pth, '.') AS pth_name,
                               jsonb_agg(e.value ORDER BY e.value::text) AS added
                        FROM excl_path p
                        CROSS JOIN LATERAL jsonb_array_elements(
                            CASE WHEN jsonb_typeof(c.new_c #> p.pth) = 'array' THEN c.new_c #> p.pth
                                 ELSE '[]'::jsonb END) e
                        WHERE NOT (CASE WHEN jsonb_typeof(c.old_c #> p.pth) = 'array'
                                        THEN c.old_c #> p.pth ELSE '[]'::jsonb END)
                                  @> jsonb_build_array(e.value)
                        GROUP BY p.pth
                        UNION ALL
                        SELECT 'conditions.users.excludeGuestsOrExternalUsers', c.new_c #> '{conditions,users,excludeGuestsOrExternalUsers}'
                        WHERE jsonb_typeof(c.new_c #> '{conditions,users,excludeGuestsOrExternalUsers}') = 'object'
                          AND jsonb_typeof(c.old_c #> '{conditions,users,excludeGuestsOrExternalUsers}')
                              IS DISTINCT FROM 'object'
                    ) z) AS exclusions_added,
                   (SELECT jsonb_object_agg(z.pth_name, z.removed ORDER BY z.pth_name) FROM (
                        SELECT array_to_string(p.pth, '.') AS pth_name,
                               jsonb_agg(e.value ORDER BY e.value::text) AS removed
                        FROM incl_path p
                        CROSS JOIN LATERAL jsonb_array_elements(
                            CASE WHEN jsonb_typeof(c.old_c #> p.pth) = 'array' THEN c.old_c #> p.pth
                                 ELSE '[]'::jsonb END) e
                        WHERE NOT (CASE WHEN jsonb_typeof(c.new_c #> p.pth) = 'array'
                                        THEN c.new_c #> p.pth ELSE '[]'::jsonb END)
                                  @> jsonb_build_array(e.value)
                        GROUP BY p.pth
                    ) z) AS inclusions_removed,
                   (jsonb_typeof(c.old_c #> '{grant_controls,authenticationStrength}') = 'object'
                    AND jsonb_typeof(c.new_c #> '{grant_controls,authenticationStrength}')
                        IS DISTINCT FROM 'object') AS auth_strength_removed,
                   (upper(COALESCE(c.old_c #>> '{grant_controls,operator}', '')) = 'AND'
                    AND upper(COALESCE(c.new_c #>> '{grant_controls,operator}', '')) = 'OR') AS and_to_or,
                   COALESCE((SELECT array_agg(x.key ORDER BY x.key)
                             FROM (SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.new_c) = 'object'
                                                                   THEN c.new_c ELSE '{}'::jsonb END)
                                   UNION
                                   SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.old_c) = 'object'
                                                                   THEN c.old_c ELSE '{}'::jsonb END)) x
                             WHERE (c.new_c -> x.key) IS DISTINCT FROM (c.old_c -> x.key)),
                            '{}'::text[]) AS changed_keys,
                   COALESCE((SELECT array_agg(x.key ORDER BY x.key)
                             FROM (SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.new_c -> 'conditions') = 'object'
                                                                   THEN c.new_c -> 'conditions' ELSE '{}'::jsonb END)
                                   UNION
                                   SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.old_c -> 'conditions') = 'object'
                                                                   THEN c.old_c -> 'conditions' ELSE '{}'::jsonb END)) x
                             WHERE (c.new_c #> ARRAY['conditions', x.key])
                                   IS DISTINCT FROM (c.old_c #> ARRAY['conditions', x.key])),
                            '{}'::text[]) AS changed_condition_keys
            FROM chg c
        ),
        cls AS (
            SELECT e.*,
                   (e.old_state = 'enabled' OR e.new_state = 'enabled') AS was_or_is_enabled,
                   array_remove(ARRAY[
                       CASE WHEN e.kind = 'removed' THEN 'deleted' END,
                       CASE WHEN e.kind = 'new' THEN 'created (state ' || COALESCE(e.new_state, '?') || ')' END,
                       CASE WHEN e.kind = 'modified' AND e.old_state = 'enabled' AND e.new_state = 'disabled'
                            THEN 'disabled' END,
                       CASE WHEN e.kind = 'modified' AND e.old_state = 'enabled'
                                 AND e.new_state = 'enabledForReportingButNotEnforced'
                            THEN 'switched to report-only' END,
                       CASE WHEN e.kind = 'modified' AND e.old_state IS DISTINCT FROM e.new_state
                                 AND NOT (e.old_state = 'enabled'
                                          AND e.new_state IN ('disabled', 'enabledForReportingButNotEnforced'))
                            THEN 'state ' || COALESCE(e.old_state, '?') || ' -> ' || COALESCE(e.new_state, '?') END,
                       CASE WHEN e.kind = 'modified' AND e.exclusions_added IS NOT NULL
                            THEN 'exclusions added ('
                                 || (SELECT string_agg(k, ', ' ORDER BY k) FROM jsonb_object_keys(e.exclusions_added) k)
                                 || ')' END,
                       CASE WHEN e.kind = 'modified' AND e.inclusions_removed IS NOT NULL
                            THEN 'targets or controls removed ('
                                 || (SELECT string_agg(k, ', ' ORDER BY k) FROM jsonb_object_keys(e.inclusions_removed) k)
                                 || ')' END,
                       CASE WHEN e.kind = 'modified' AND e.auth_strength_removed
                            THEN 'authentication strength removed' END,
                       CASE WHEN e.kind = 'modified' AND e.and_to_or
                            THEN 'grant operator AND -> OR' END
                   ], NULL) AS changes
            FROM eval e
        ),
        ca_finding AS (
            SELECT c.*,
                   CASE
                       WHEN c.kind = 'removed' AND c.old_state = 'enabled' THEN 'high'
                       WHEN c.kind = 'modified' AND c.old_state = 'enabled'
                            AND c.new_state IN ('disabled', 'enabledForReportingButNotEnforced') THEN 'high'
                       WHEN c.kind = 'modified' AND c.was_or_is_enabled
                            AND (c.exclusions_added IS NOT NULL OR c.inclusions_removed IS NOT NULL
                                 OR c.auth_strength_removed OR c.and_to_or) THEN 'high'
                       ELSE 'medium'
                   END AS severity
            FROM cls c
        ),
        sd AS (
            SELECT ov.content AS old_c, nv.content AS new_c
            FROM bt
            JOIN entra_change_history nv
              ON nv.client_id = bt.client_id AND nv.entity_type = 'tenant_policy'
             AND nv.entity_key = 'security_defaults' AND nv.valid_from = bt.last_run_at AND nv.valid_to IS NULL
            JOIN entra_change_history ov
              ON ov.client_id = bt.client_id AND ov.entity_type = 'tenant_policy'
             AND ov.entity_key = 'security_defaults' AND ov.valid_to = bt.last_run_at
            WHERE (ov.content->>'enabled') = 'true'
              AND (nv.content->>'enabled') IS DISTINCT FROM 'true'
        )
        SELECT
            CASE WHEN f.severity = 'high' THEN 'fail' ELSE 'warn' END AS status,
            CASE WHEN f.entity_key ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                 THEN f.entity_key::uuid
                 ELSE md5('11025:' || %(client_id)s::text || ':' || f.entity_key)::uuid END AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            f.severity AS fd_severity,
            'Conditional Access policy "' || f.label || '" '
                || CASE WHEN cardinality(f.changes) > 0 THEN array_to_string(f.changes, '; ')
                        ELSE 'modified (' || array_to_string(f.changed_keys, ', ') || ')' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'policy_id', f.entity_key,
                'policy_name', f.label,
                'change', f.kind,
                'previous_state', f.old_state,
                'current_state', f.new_state,
                'changed_keys', to_jsonb(f.changed_keys),
                'changed_condition_keys', to_jsonb(f.changed_condition_keys),
                'exclusions_added', f.exclusions_added,
                'inclusions_or_controls_removed', f.inclusions_removed,
                'authentication_strength_removed', f.auth_strength_removed,
                'operator_and_to_or', f.and_to_or,
                'previous', f.old_c,
                'current', f.new_c,
                'detected_at', (SELECT last_run_at FROM bc)
            ) AS detail
        FROM ca_finding f
        UNION ALL
        SELECT
            'fail',
            md5('11025:' || %(client_id)s::text || ':security_defaults')::uuid,
            NULL, NULL, NULL, NULL,
            'high',
            'Security Defaults was turned off since the previous Entra collection',
            jsonb_build_object('previous', s.old_c, 'current', s.new_c,
                               'detected_at', (SELECT last_run_at FROM bt))
        FROM sd s
    """,
}
