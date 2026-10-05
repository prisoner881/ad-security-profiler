"""
Plugin 9020: Group Policy Adds Broad Principals to Local Administrators

Reports GPOs that add a broad principal -- Everyone (S-1-1-0),
Authenticated Users (S-1-5-11), Users (S-1-5-32-545), Domain Users (-513)
or Domain Computers (-515) of any domain -- to the local Administrators
group (S-1-5-32-544) of the computers they apply to, through either
mechanism Group Policy has:

- Group Policy Preferences, Local Users and Groups (Groups.xml): a Group
  item for Administrators (groupSid S-1-5-32-544, or a group name starting
  with "Administrators", e.g. "Administrators (built-in)") whose member
  list ADDs a broad principal -- by SID, or by name ("Everyone",
  "Authenticated Users", "<DOMAIN>\\Domain Users", ...) when the item has no
  SID. Items whose own action is Delete are ignored.
- Restricted Groups (GptTmpl.inf [Group Membership]): a
  "*S-1-5-32-544__Members" (or "Administrators__Members") key whose value
  lists a broad principal, or a "<broad principal>__Memberof" key whose
  value lists Administrators.

Why: every user (or computer) in the domain becomes a local administrator
of every computer the GPO applies to -- credential theft from any of those
machines and lateral movement with any account (MITRE ATT&CK T1098,
T1078.002). On a domain controller, local Administrators is the domain's
BUILTIN\\Administrators: every domain user becomes a domain administrator.

Severity: critical when the GPO applies to a domain controller
(v_gpo_dc_application precedence not NULL); high when it has any enabled
link (it applies somewhere); low (status warn) when it is not linked or
all links are disabled -- not effective now, but one link away. Site links
and WMI filters are not evaluated. One row per GPO. Zero rows unless
SYSVOL has been collected (adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9020,
    "category": "Organizational Units",
    "name": "Group Policy Adds Broad Principals to Local Administrators",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9020",
    "framework_tags": [
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4", "CIS-CSC-8-6.8", "ISO-27001-2022-A.8.2", "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "NIST-800-53-AC-6", "ISO-27001-2022-A.5.15",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
        {"title": "MITRE ATT&CK T1078.002: Valid Accounts: Domain Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/002/"},
    ],
    "description": (
        "Reports GPOs that add Everyone, Authenticated Users, Users, Domain Users or "
        "Domain Computers to the local Administrators group, through Group Policy "
        "Preferences (Local Users and Groups) or Restricted Groups. Every account in the "
        "domain then administers every computer the GPO applies to; on a domain "
        "controller that means domain admin. Critical when the GPO applies to a domain "
        "controller, high when it is linked anywhere, low when it is not linked. One row "
        "per GPO. Requires SYSVOL collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Edit the GPO: in Computer Configuration > Preferences > Control Panel Settings > "
        "Local Users and Groups, remove the broad member from the Administrators item; in "
        "Computer Configuration > Policies > Windows Settings > Security Settings > "
        "Restricted Groups, remove it from the Administrators Members list (or the "
        "group's Member Of entry). Grant local administration to a dedicated, small "
        "group per tier instead (and use Windows LAPS for the built-in account). Run "
        "gpupdate /force and verify with 'Get-LocalGroupMember Administrators' on an "
        "affected computer; if the GPO applied to a domain controller, review "
        "BUILTIN\\Administrators membership and treat the domain as exposed for the "
        "period the setting was in place."
    ),
    "base_severity": "high",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        broad_name (short_name, label) AS (
            VALUES ('everyone', 'Everyone'), ('authenticated users', 'Authenticated Users'),
                   ('users', 'Users'), ('domain users', 'Domain Users'),
                   ('domain computers', 'Domain Computers')
        ),
        gpp_member AS (
            SELECT p.gpo_guid, p.scope, p.item_name,
                   m.value ->> 'sid' AS member_sid, m.value ->> 'name' AS member_name
            FROM gpo_preference_item_edge p
            CROSS JOIN sysvol sv
            CROSS JOIN LATERAL jsonb_array_elements(
                CASE WHEN jsonb_typeof(p.details_json::jsonb -> 'members') = 'array'
                     THEN p.details_json::jsonb -> 'members' ELSE '[]'::jsonb END) AS m(value)
            WHERE sv.collected
              AND p.client_id = %(client_id)s
              AND p.valid_to IS NULL
              AND p.preference_type = 'Groups'
              AND upper(COALESCE(p.action, 'U')) <> 'D'
              AND (upper(p.details_json::jsonb ->> 'group_sid') = 'S-1-5-32-544'
                   OR lower(p.details_json::jsonb ->> 'group_name') LIKE 'administrators%%')
              AND upper(COALESCE(m.value ->> 'action', '')) = 'ADD'
        ),
        rg_entry AS (
            -- Restricted Groups: Administrators__Members = <list>
            SELECT s.gpo_guid, s.scope, btrim(x) AS entry, 'members' AS kind
            FROM gpo_setting_edge s
            CROSS JOIN sysvol sv
            CROSS JOIN LATERAL unnest(string_to_array(COALESCE(s.setting_value, ''), ',')) AS x
            WHERE sv.collected
              AND s.client_id = %(client_id)s AND s.valid_to IS NULL
              AND s.source = 'security_template' AND lower(s.section) = 'group membership'
              AND right(lower(s.setting_key), 9) = '__members'
              AND lower(left(s.setting_key, length(s.setting_key) - 9))
                  IN ('*s-1-5-32-544', 'administrators', 'builtin' || chr(92) || 'administrators')
              AND btrim(x) <> ''
            UNION ALL
            -- Restricted Groups: <principal>__Memberof = <list containing Administrators>
            SELECT s.gpo_guid, s.scope, left(s.setting_key, length(s.setting_key) - 10), 'memberof'
            FROM gpo_setting_edge s
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND s.client_id = %(client_id)s AND s.valid_to IS NULL
              AND s.source = 'security_template' AND lower(s.section) = 'group membership'
              AND right(lower(s.setting_key), 10) = '__memberof'
              AND EXISTS (SELECT 1 FROM unnest(string_to_array(COALESCE(s.setting_value, ''), ',')) AS y
                          WHERE lower(btrim(y)) IN ('*s-1-5-32-544', 'administrators',
                                                    'builtin' || chr(92) || 'administrators'))
        ),
        candidate AS (
            SELECT gm.gpo_guid, gm.scope,
                   'Group Policy Preferences item "' || COALESCE(gm.item_name, 'Administrators') || '"' AS via,
                   upper(NULLIF(btrim(gm.member_sid), '')) AS sid,
                   gm.member_name AS name
            FROM gpp_member gm
            UNION ALL
            SELECT r.gpo_guid, r.scope,
                   CASE r.kind WHEN 'members' THEN 'Restricted Groups (Administrators members)'
                               ELSE 'Restricted Groups (member of Administrators)' END,
                   CASE WHEN left(r.entry, 1) = '*' THEN upper(substr(r.entry, 2)) END,
                   CASE WHEN left(r.entry, 1) = '*' THEN NULL ELSE r.entry END
            FROM rg_entry r
        ),
        hit AS (
            SELECT c.gpo_guid, c.scope, c.via, c.sid, c.name,
                   CASE
                       WHEN c.sid = 'S-1-1-0' THEN 'Everyone'
                       WHEN c.sid = 'S-1-5-11' THEN 'Authenticated Users'
                       WHEN c.sid = 'S-1-5-32-545' THEN 'Users'
                       WHEN c.sid ~ '^S-1-5-21-[0-9-]+-513$' THEN 'Domain Users'
                       WHEN c.sid ~ '^S-1-5-21-[0-9-]+-515$' THEN 'Domain Computers'
                       WHEN c.sid IS NULL THEN
                           (SELECT bn.label FROM broad_name bn
                             WHERE bn.short_name = lower(btrim(reverse(split_part(reverse(COALESCE(c.name, '')), chr(92), 1)))))
                   END AS broad_label
            FROM candidate c
        ),
        per_gpo AS (
            SELECT h.gpo_guid,
                   string_agg(DISTINCT h.broad_label, ', ' ORDER BY h.broad_label) AS principals,
                   string_agg(DISTINCT h.via, '; ' ORDER BY h.via) AS vias,
                   jsonb_agg(jsonb_build_object(
                       'principal', h.broad_label, 'sid', h.sid, 'name', h.name,
                       'scope', h.scope, 'via', h.via)
                       ORDER BY h.broad_label, h.via, h.sid, h.name) AS additions
            FROM hit h
            WHERE h.broad_label IS NOT NULL
            GROUP BY h.gpo_guid
        ),
        rated AS (
            SELECT p.*,
                   EXISTS (SELECT 1 FROM v_gpo_dc_application a
                           WHERE a.client_id = %(client_id)s AND a.gpo_guid = p.gpo_guid
                             AND a.precedence IS NOT NULL) AS applies_to_dc,
                   EXISTS (SELECT 1 FROM gpo_link_edge l
                           WHERE l.client_id = %(client_id)s AND l.gpo_guid = p.gpo_guid
                             AND l.valid_to IS NULL AND l.link_enabled) AS linked
            FROM per_gpo p
        )
        SELECT
            CASE WHEN r.applies_to_dc OR r.linked THEN 'fail' ELSE 'warn' END AS status,
            r.gpo_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN r.applies_to_dc THEN 'critical'
                 WHEN r.linked THEN 'high'
                 ELSE 'low' END AS fd_severity,
            'GPO "' || COALESCE(g.display_name, d.dn_current) || '" adds ' || r.principals
                || ' to the local Administrators group via ' || r.vias
                || CASE WHEN r.applies_to_dc THEN ' and applies to domain controllers'
                        WHEN r.linked THEN ''
                        ELSE ' (GPO not linked or all links disabled)' END AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', d.dn_current,
                'additions', r.additions,
                'applies_to_domain_controller', r.applies_to_dc,
                'has_enabled_link', r.linked,
                'linked_containers', (
                    SELECT jsonb_agg(jsonb_build_object('container_dn', cd.dn_current,
                                                        'link_enabled', l.link_enabled,
                                                        'link_enforced', l.link_enforced)
                                     ORDER BY cd.dn_current)
                    FROM gpo_link_edge l
                    JOIN directory_object cd
                      ON cd.object_guid = l.container_guid AND cd.client_id = l.client_id
                    WHERE l.client_id = %(client_id)s AND l.gpo_guid = r.gpo_guid
                      AND l.valid_to IS NULL)
            ) AS detail
        FROM rated r
        JOIN directory_object d
          ON d.object_guid = r.gpo_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        LEFT JOIN ad_gpo g
          ON g.object_guid = r.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
    """,
}
