"""
Plugin 11027: New Owner on an Application, Service Principal or Sensitive Group

Change Detection for Microsoft Entra ID. Reports owners added, in the latest
Entra collection, to an application registration, a service principal or a
sensitive group (role-assignable, holding a directory role, referenced by
Conditional Access, or granted a privileged app role -- the groups whose
owners the collector reads).

Why: an owner of an application or service principal can add credentials to
it and act as the application with all its permissions; an owner of a group
can change its membership -- adding an account to a role-assignable group,
or to a Conditional Access exclusion group. Adding an owner is a quiet way to
prepare an escalation or persistence path that no role-assignment alert
covers (MITRE ATT&CK T1098 Account Manipulation; T1098.001 for apps).

Data: entra_change_history entity_type 'owner' (key <owned object id>:<owner
id>; content {owned_object_type 'application' | 'servicePrincipal' |
'group', owned_object_id, owned_display_name, owner_id, owner_type,
owner_display_name, owner_upn}) and entra_change_baseline. Only NEW owner
entries (no earlier version of the key) are reported. Enrichment: the
group's sensitive_reasons (entra_group). Suppressed on the first collection;
findings stay open until the next Entra collection.

Severity: high. Medium when the owned object is an application registration
created after the previous owner snapshot (entra_application.created_at):
that is the creator becoming the initial owner of a new app. One row per
(owned object, owner) (object_guid = md5('11027:' || client_id || ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11027,
    "category": "Change Detection",
    "name": "New Owner on an Application, Service Principal or Sensitive Group",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11027",
    "requires_sources": ["app_owners", "groups"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "Microsoft: Overview of enterprise application ownership",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners"},
        {"title": "Microsoft: Use Microsoft Entra groups to manage role assignments (role-assignable groups)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
    ],
    "description": (
        "Reports owners added since the previous Entra collection to application "
        "registrations, service principals and sensitive groups (role-assignable, holding a "
        "role, used by Conditional Access or granted a privileged app role). An application "
        "owner can add credentials and act as the app; a group owner can change membership. "
        "Initial owners of newly created applications are reported at medium. Suppressed on "
        "the first Entra collection."
    ),
    "remediation": (
        "Confirm the owner against an approved request (Entra audit log: 'Add owner to "
        "application', 'Add owner to service principal', 'Add owner to group'). Remove "
        "unapproved owners (Remove-MgApplicationOwnerByRef, "
        "Remove-MgServicePrincipalOwnerByRef, Remove-MgGroupOwnerByRef), check whether "
        "credentials or members were added afterwards (plugins 11023, 11029, 11020), and "
        "keep privileged applications and role-assignable groups owned only by Tier 0 "
        "administrators or by nobody."
    ),
    "base_severity": "high",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at,
                   (SELECT max(GREATEST(h.valid_from, COALESCE(h.valid_to, h.valid_from)))
                    FROM entra_change_history h
                    WHERE h.client_id = bl.client_id AND h.entity_type = 'owner'
                      AND h.valid_from < bl.last_run_at
                      AND COALESCE(h.valid_to, h.valid_from) < bl.last_run_at) AS prev_seen_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'owner'
              AND bl.first_run_at < bl.last_run_at
        ),
        new_owner AS (
            SELECT h.entity_key, h.entity_label, h.content,
                   CASE WHEN h.content->>'owned_object_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        THEN (h.content->>'owned_object_id')::uuid END AS owned_id,
                   b.prev_seen_at
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'owner'
              AND h.valid_from = b.last_run_at
              AND h.valid_to IS NULL
              AND NOT EXISTS (SELECT 1 FROM entra_change_history e
                              WHERE e.client_id = h.client_id AND e.entity_type = h.entity_type
                                AND e.entity_key = h.entity_key AND e.valid_from < b.last_run_at)
        ),
        enriched AS (
            SELECT n.*,
                   g.sensitive_reasons,
                   g.is_assignable_to_role,
                   a.created_at AS app_created_at,
                   (n.content->>'owned_object_type' = 'application'
                    AND a.created_at IS NOT NULL
                    AND n.prev_seen_at IS NOT NULL
                    AND a.created_at >= n.prev_seen_at) AS initial_owner_of_new_app
            FROM new_owner n
            LEFT JOIN entra_group g
              ON g.client_id = %(client_id)s AND g.entra_object_id = n.owned_id
             AND n.content->>'owned_object_type' = 'group'
            LEFT JOIN entra_application a
              ON a.client_id = %(client_id)s AND a.entra_object_id = n.owned_id
             AND n.content->>'owned_object_type' = 'application'
        )
        SELECT
            CASE WHEN e.initial_owner_of_new_app THEN 'warn' ELSE 'fail' END AS status,
            md5('11027:' || %(client_id)s::text || ':' || e.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN e.initial_owner_of_new_app THEN 'medium' ELSE 'high' END AS fd_severity,
            'New owner '
                || CASE e.content->>'owner_type'
                       WHEN '#microsoft.graph.user' THEN 'user '
                       WHEN '#microsoft.graph.servicePrincipal' THEN 'service principal '
                       ELSE '' END
                || '"' || COALESCE(e.content->>'owner_upn', e.content->>'owner_display_name',
                                   e.content->>'owner_id', '?') || '" on '
                || CASE e.content->>'owned_object_type'
                       WHEN 'servicePrincipal' THEN 'service principal'
                       WHEN 'group' THEN 'group'
                       ELSE 'application' END
                || ' "' || COALESCE(e.content->>'owned_display_name', e.entity_label,
                                    e.content->>'owned_object_id', '?') || '"'
                || CASE WHEN e.content->>'owned_object_type' = 'group'
                             AND cardinality(e.sensitive_reasons) > 0
                        THEN ' (' || array_to_string(e.sensitive_reasons, ', ') || ')' ELSE '' END
                || CASE WHEN e.initial_owner_of_new_app THEN ' (newly created application)' ELSE '' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'owned_object_type', e.content->>'owned_object_type',
                'owned_object_id', e.content->>'owned_object_id',
                'owned_display_name', e.content->>'owned_display_name',
                'owner_id', e.content->>'owner_id',
                'owner_type', e.content->>'owner_type',
                'owner_display_name', e.content->>'owner_display_name',
                'owner_upn', e.content->>'owner_upn',
                'group_sensitive_reasons', to_jsonb(e.sensitive_reasons),
                'group_is_assignable_to_role', e.is_assignable_to_role,
                'application_created_at', e.app_created_at,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM enriched e
    """,
}
