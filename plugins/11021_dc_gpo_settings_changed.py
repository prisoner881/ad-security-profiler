"""
Plugin 11021: Group Policy Settings Changed in GPOs That Apply to Domain Controllers

Change Detection over SYSVOL content. Reports, per GPO, the Group Policy
settings that changed in this run:

- in GPOs that apply to at least one domain controller
  (v_gpo_dc_application precedence NOT NULL): every gpo_setting_edge row
  opened (run_id_valid_from = this run) or closed (run_id_valid_to = this
  run). A closed and an opened row with the same (scope, source, section,
  key) are paired into "old -> new"; an opened row alone is an added
  setting, a closed row alone a removed one. Group Policy Preferences items
  (scheduled tasks, local groups, services, ...) added, changed or removed
  in those GPOs are reported the same way;
- in ANY GPO: a Group Policy Preferences item that newly carries a
  cpassword (MS14-025 -- readable by every domain user).

Why: a GPO that applies to domain controllers is code execution and
policy control on them. Plugin 11013 sees an edit only through the AD
versionNumber; this plugin sees what changed -- user rights, restricted
groups, LDAP/SMB signing, NTLM level, WDigest, audit policy, scheduled
tasks -- and also catches edits made directly on SYSVOL without bumping
the AD version (MITRE ATT&CK T1484.001).

Severity: high when a change touches [Privilege Rights] or [Group
Membership], LDAP signing / channel binding, SMB signing, LmCompatibilityLevel
or WDigest (UseLogonCredential / Negotiate) registry values, a GPP Groups
item, or adds a cpassword; medium otherwise. status warn. One row per GPO;
the summary lists up to ten changes (sorted) and detail lists them all.
Values shown are as collected: credential-like registry values are
'<redacted>', cpasswords are never collected.

Baseline: a GPO's first SYSVOL collection is not a change. A GPO qualifies
when it already had a setting or preference edge opened in an earlier run,
or when it was first seen in AD after the client's first SYSVOL collection
(a new GPO's settings are new). A GPO whose folder could not be read keeps
its previous settings (the collector carries them forward), so an
unreadable folder does not look like removed settings. Changes made and
reverted between two runs are not observed.
"""

PLUGIN = {
    "plugin_id": 11021,
    "category": "Change Detection",
    "name": "Group Policy Settings Changed in GPOs That Apply to Domain Controllers",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11021",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32",
        "SOC2-CC7.2", "SOC2-CC8.1", "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.001",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
        {"title": "Microsoft Security Bulletin MS14-025: Vulnerability in Group Policy Preferences could allow elevation of privilege",
         "url": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025"},
    ],
    "description": (
        "Reports Group Policy settings changed since the previous SYSVOL collection in "
        "GPOs that apply to domain controllers -- security template entries (user rights, "
        "restricted groups, Kerberos and account policy, services), registry-based "
        "settings, advanced audit policy and Group Policy Preferences items -- shown as "
        "old -> new, added or removed; plus any GPO that newly stores a Group Policy "
        "Preferences password (cpassword). High when user rights, group membership, "
        "LDAP/SMB signing, LmCompatibilityLevel, WDigest or local groups change or a "
        "cpassword is added; medium otherwise. A GPO's first SYSVOL collection is a "
        "baseline, not a change. One row per GPO."
    ),
    "remediation": (
        "Confirm each change against a change record. Find who made it: event 5136 on the "
        "GPO object (versionNumber) and, if SYSVOL file auditing is enabled, events "
        "4663/5145 on the GPO folder; GPMC (or Get-GPOReport -Guid <guid> -ReportType "
        "Html) shows the current settings -- compare with a backup (Backup-GPO) or AGPM "
        "history. Revert unapproved changes with Restore-GPO and investigate the account "
        "that made them; if a user right, restricted group or GPP local group change "
        "granted access on domain controllers, treat it as a possible compromise. Remove "
        "any new cpassword item and reset that account's password. Restrict edit rights "
        "on DC-applying GPOs and write access to SYSVOL to Tier 0 administrators."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        baseline AS (
            SELECT min(x.r) AS first_run
            FROM (SELECT min(run_id_valid_from) AS r FROM gpo_setting_edge
                   WHERE client_id = %(client_id)s
                  UNION ALL
                  SELECT min(run_id_valid_from) FROM gpo_preference_item_edge
                   WHERE client_id = %(client_id)s) x
        ),
        dc_gpo AS (
            SELECT DISTINCT a.gpo_guid
            FROM v_gpo_dc_application a
            WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
        ),
        eligible AS (
            SELECT d.object_guid AS gpo_guid
            FROM directory_object d
            CROSS JOIN baseline b
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND d.client_id = %(client_id)s
              AND NOT d.is_deleted
              AND (EXISTS (SELECT 1 FROM gpo_setting_edge e
                           WHERE e.client_id = %(client_id)s AND e.gpo_guid = d.object_guid
                             AND e.run_id_valid_from < %(run_id)s)
                   OR EXISTS (SELECT 1 FROM gpo_preference_item_edge e
                              WHERE e.client_id = %(client_id)s AND e.gpo_guid = d.object_guid
                                AND e.run_id_valid_from < %(run_id)s)
                   OR (b.first_run < %(run_id)s AND d.first_seen_run_id > b.first_run))
        ),
        s_opened AS (
            SELECT e.gpo_guid, e.scope, e.source, e.section, e.setting_key, e.value_type, e.setting_value
            FROM gpo_setting_edge e
            WHERE e.client_id = %(client_id)s AND e.run_id_valid_from = %(run_id)s
              AND e.gpo_guid IN (SELECT gpo_guid FROM dc_gpo)
        ),
        s_closed AS (
            SELECT e.gpo_guid, e.scope, e.source, e.section, e.setting_key, e.value_type, e.setting_value
            FROM gpo_setting_edge e
            WHERE e.client_id = %(client_id)s AND e.run_id_valid_to = %(run_id)s
              AND e.gpo_guid IN (SELECT gpo_guid FROM dc_gpo)
        ),
        s_change AS (
            SELECT COALESCE(o.gpo_guid, c.gpo_guid) AS gpo_guid,
                   COALESCE(o.scope, c.scope) AS scope,
                   COALESCE(o.source, c.source) AS source,
                   COALESCE(o.section, c.section) AS section,
                   COALESCE(o.setting_key, c.setting_key) AS setting_key,
                   COALESCE(o.value_type, c.value_type) AS value_type,
                   c.setting_value AS old_value,
                   o.setting_value AS new_value,
                   CASE WHEN c.gpo_guid IS NULL THEN 'added'
                        WHEN o.gpo_guid IS NULL THEN 'removed'
                        ELSE 'modified' END AS change_kind
            FROM s_opened o
            FULL JOIN s_closed c
              ON c.gpo_guid = o.gpo_guid AND c.scope = o.scope AND c.source = o.source
             AND lower(c.section) = lower(o.section) AND lower(c.setting_key) = lower(o.setting_key)
        ),
        s_rows AS (
            SELECT sc.gpo_guid,
                   CASE sc.source
                        WHEN 'security_template' THEN '[' || sc.section || '] ' || sc.setting_key
                        WHEN 'registry' THEN sc.section || '\' || sc.setting_key
                        ELSE 'Advanced audit: ' || COALESCE(sc.value_type, sc.setting_key)
                   END
                   || CASE WHEN sc.scope = 'user' THEN ' (user)' ELSE '' END AS label,
                   sc.change_kind, sc.old_value, sc.new_value,
                   (lower(sc.section) IN ('privilege rights', 'group membership')
                    OR (sc.source = 'registry' AND lower(sc.setting_key) IN (
                        'system\currentcontrolset\services\ntds\parameters\ldapserverintegrity',
                        'system\currentcontrolset\services\ntds\parameters\ldapenforcechannelbinding',
                        'system\currentcontrolset\services\ldap\ldapclientintegrity',
                        'system\currentcontrolset\services\lanmanserver\parameters\requiresecuritysignature',
                        'system\currentcontrolset\services\lanmanserver\parameters\enablesecuritysignature',
                        'system\currentcontrolset\services\lanmanworkstation\parameters\requiresecuritysignature',
                        'system\currentcontrolset\services\lanmanworkstation\parameters\enablesecuritysignature',
                        'system\currentcontrolset\control\lsa\lmcompatibilitylevel',
                        'system\currentcontrolset\control\securityproviders\wdigest\uselogoncredential',
                        'system\currentcontrolset\control\securityproviders\wdigest\negotiate'))
                   ) AS high_impact,
                   false AS cpassword_added,
                   'setting' AS item_kind
            FROM s_change sc
            WHERE sc.gpo_guid IN (SELECT gpo_guid FROM eligible)
        ),
        p_opened AS (
            SELECT e.* FROM gpo_preference_item_edge e
            WHERE e.client_id = %(client_id)s AND e.run_id_valid_from = %(run_id)s
        ),
        p_closed AS (
            SELECT e.* FROM gpo_preference_item_edge e
            WHERE e.client_id = %(client_id)s AND e.run_id_valid_to = %(run_id)s
        ),
        p_change AS (
            SELECT COALESCE(o.gpo_guid, c.gpo_guid) AS gpo_guid,
                   COALESCE(o.scope, c.scope) AS scope,
                   COALESCE(o.preference_type, c.preference_type) AS preference_type,
                   COALESCE(o.item_name, c.item_name, COALESCE(o.item_uid, c.item_uid)) AS item_name,
                   c.gpo_guid IS NULL AS is_added,
                   o.gpo_guid IS NULL AS is_removed,
                   COALESCE(o.has_cpassword, false) AND NOT COALESCE(c.has_cpassword, false) AS cpassword_added,
                   c.action AS old_action, o.action AS new_action,
                   c.account_name AS old_account, o.account_name AS new_account,
                   c.has_cpassword AS old_cpassword, o.has_cpassword AS new_cpassword,
                   c.details_json AS old_details, o.details_json AS new_details
            FROM p_opened o
            FULL JOIN p_closed c
              ON c.gpo_guid = o.gpo_guid AND c.scope = o.scope
             AND c.preference_type = o.preference_type AND c.item_uid = o.item_uid
        ),
        p_rows AS (
            SELECT pc.gpo_guid,
                   'Preferences ' || pc.preference_type || ' "' || pc.item_name || '"'
                       || CASE WHEN pc.scope = 'user' THEN ' (user)' ELSE '' END AS label,
                   CASE WHEN pc.is_added THEN 'added' WHEN pc.is_removed THEN 'removed'
                        ELSE 'modified' END AS change_kind,
                   CASE WHEN pc.is_added THEN NULL
                        ELSE 'action ' || COALESCE(pc.old_action, '-') || COALESCE(', account ' || pc.old_account, '')
                             || CASE WHEN pc.old_cpassword THEN ', cpassword' ELSE '' END END AS old_value,
                   CASE WHEN pc.is_removed THEN NULL
                        ELSE 'action ' || COALESCE(pc.new_action, '-') || COALESCE(', account ' || pc.new_account, '')
                             || CASE WHEN pc.new_cpassword THEN ', cpassword' ELSE '' END END AS new_value,
                   (pc.preference_type = 'Groups' OR pc.cpassword_added) AS high_impact,
                   pc.cpassword_added,
                   'preference' AS item_kind
            FROM p_change pc
            WHERE pc.gpo_guid IN (SELECT gpo_guid FROM eligible)
              AND (pc.gpo_guid IN (SELECT gpo_guid FROM dc_gpo) OR pc.cpassword_added)
        ),
        all_rows AS (
            SELECT r.*,
                   r.label || ': ' || COALESCE(left(r.old_value, 60), '(not set)')
                       || ' -> ' || COALESCE(left(r.new_value, 60), '(not set)') AS change_text
            FROM (SELECT * FROM s_rows UNION ALL SELECT * FROM p_rows) r
        ),
        numbered AS (
            SELECT a.*, row_number() OVER (PARTITION BY a.gpo_guid ORDER BY a.change_text) AS rn
            FROM all_rows a
        ),
        per_gpo AS (
            SELECT n.gpo_guid,
                   count(*) AS change_count,
                   bool_or(n.high_impact) AS high_impact,
                   bool_or(n.cpassword_added) AS cpassword_added,
                   string_agg(n.change_text, '; ' ORDER BY n.change_text) FILTER (WHERE n.rn <= 10) AS first_changes,
                   jsonb_agg(jsonb_build_object(
                       'item_kind', n.item_kind, 'setting', n.label, 'change', n.change_kind,
                       'old_value', n.old_value, 'new_value', n.new_value,
                       'high_impact', n.high_impact, 'cpassword_added', n.cpassword_added)
                       ORDER BY n.change_text) AS changes
            FROM numbered n
            GROUP BY n.gpo_guid
        )
        SELECT
            'warn' AS status,
            p.gpo_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.high_impact THEN 'high' ELSE 'medium' END AS fd_severity,
            'GPO "' || COALESCE(g.display_name, d.dn_current) || '"'
                || CASE WHEN p.gpo_guid IN (SELECT gpo_guid FROM dc_gpo)
                        THEN ', which applies to domain controllers,' ELSE '' END
                || ' had ' || p.change_count || ' Group Policy change(s) since the previous collection'
                || CASE WHEN p.cpassword_added THEN ', including a new Group Policy Preferences password (cpassword)' ELSE '' END
                || ': ' || p.first_changes
                || CASE WHEN p.change_count > 10 THEN '; and ' || (p.change_count - 10) || ' more' ELSE '' END
                AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', d.dn_current,
                'applies_to_domain_controller', p.gpo_guid IN (SELECT gpo_guid FROM dc_gpo),
                'ad_version_number', g.version_number,
                'sysvol_gpt_ini_version', gs.gpt_ini_version,
                'changes', p.changes,
                'corroborating_event_ids', jsonb_build_array(5136, 4663, 5145)
            ) AS detail
        FROM per_gpo p
        JOIN directory_object d
          ON d.object_guid = p.gpo_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        LEFT JOIN ad_gpo g
          ON g.object_guid = p.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        LEFT JOIN ad_gpo_sysvol gs
          ON gs.gpo_object_guid = p.gpo_guid AND gs.client_id = %(client_id)s
    """,
}
