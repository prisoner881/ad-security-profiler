"""
Plugin 10086: Public Microsoft 365 Groups

Reports Microsoft 365 groups (groupTypes contains 'Unified') with
visibility 'Public'.

Why: any member of the tenant can find a public Microsoft 365 group, join
it without approval and read its conversations, files, calendar and Teams
channel. Groups created for projects or departments often end up holding
sensitive documents, and membership may also grant access to applications
or licences. CIS M365 1.2.1 ("only organizationally managed/approved
public groups exist"); Tenable, Monkey365, EntraFalcon GRP-003.

Severity: medium (fail) when the group is also sensitive
(entra_group.sensitive_reasons: Conditional Access include / exclude
lists, or an app role on a privileged application) -- joining it changes
what a user is subject to or can reach; otherwise low (warn) to confirm
the group is meant to be public. One finding per group (object_guid
md5('10086:' || client_id || ':' || group id)). visibility is collected
from entra_graph_collector 0.9.0.
"""

PLUGIN = {
    "plugin_id": 10086,
    "category": "Hybrid Identity",
    "name": "Public Microsoft 365 Groups",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10086",
    "requires_sources": ["groups"],
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-01",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1213",
    ],
    "references": [
        {"title": "Microsoft: Manage Microsoft 365 groups (privacy: public or private)",
         "url": "https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/manage-groups"},
        {"title": "Microsoft Graph: group resource type (visibility)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/group"},
        {"title": "MITRE ATT&CK T1213: Data from Information Repositories",
         "url": "https://attack.mitre.org/techniques/T1213/"},
    ],
    "description": (
        "A Microsoft 365 group is public: any user in the tenant can join it without "
        "approval and read its mail, files and Teams content. Medium when the group is also "
        "used by Conditional Access or grants access to a privileged application, low "
        "otherwise."
    ),
    "remediation": (
        "Microsoft 365 admin center > Teams & groups > Active teams & groups > the group > "
        "Settings > Privacy = Private (Set-UnifiedGroup -AccessType Private). Restrict who "
        "can create groups (plugin 10081) and set a sensitivity label policy that defaults "
        "new groups to private."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            CASE WHEN g.sensitive_reasons && ARRAY['ca_include', 'ca_exclude', 'app_role'] THEN 'fail'
                 ELSE 'warn' END AS status,
            md5('10086:' || g.client_id::text || ':' || g.entra_object_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.sensitive_reasons && ARRAY['ca_include', 'ca_exclude', 'app_role'] THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            'Microsoft 365 group "' || COALESCE(g.display_name, g.entra_object_id::text)
                || '" is public: anyone in the tenant can join it'
                || CASE WHEN g.sensitive_reasons && ARRAY['ca_include', 'ca_exclude', 'app_role']
                        THEN ' (it is used by ' || array_to_string(g.sensitive_reasons, ', ') || ')'
                        ELSE '' END AS summary,
            jsonb_build_object('group', g.display_name, 'group_id', g.entra_object_id,
                               'visibility', g.visibility, 'group_types', g.group_types,
                               'sensitive_reasons', g.sensitive_reasons) AS detail
        FROM entra_group g
        WHERE g.client_id = %(client_id)s
          AND g.group_types @> ARRAY['Unified']
          AND g.visibility = 'Public'
    """,
}
