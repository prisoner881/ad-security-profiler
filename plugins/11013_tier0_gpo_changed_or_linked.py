"""
Plugin 11013: GPO Applying to Tier 0 Modified or Newly Linked

Change Detection: reports Group Policy Objects that apply to Tier 0 and
changed since the previous successful collection run -- either the GPO's
content was edited (its versionNumber changed) or a link from a Tier 0
scope to it was added (or re-enabled).

Tier 0 scopes (containers whose GPO links apply to Tier 0 systems or
accounts):
- the domain root (applies to every object, DCs and admins included);
- an OU containing domain controllers (v_tier0_object
  'domain_controller_ou', every OU above a DC);
- an AD site (site GPOs apply to the DCs in that site);
- any other OU containing a Tier 0 object (v_tier0_object: CA hosts,
  ...) or a Tier 0 account (v_privileged_principal: user settings of a
  GPO linked above an admin account run in that admin's logon session).

Why: a GPO that applies to domain controllers or administrators is code
execution on them -- scheduled tasks, startup scripts, restricted-groups
and user-rights settings (MITRE ATT&CK T1484.001, Group Policy
Modification). GPO abuse is a standard ransomware deployment and
persistence technique. Edits to these GPOs and new links at these scopes
are rare and should match a change record.

Detection details:
- Modified: the current ad_gpo version was written since the previous
  succeeded sync_run and its version_number differs from the version
  current at that run. Only version_number is compared, so the gPCFileSysPath
  and flags columns schema v38 adds to every GPO (a new version of every
  GPO in its first run) are not changes; NULL -> value is "not
  previously collected". The GPO must currently have an enabled link to
  a Tier 0 scope.
- Newly linked: an enabled gpo_link_edge to a Tier 0 scope opened since
  the previous run where no enabled link between the same container and
  GPO was open at that run (a link-order change reopens the edge and is
  not reported; a disabled link being enabled is). Site gPLinks are
  collected from collector 0.5.16 on: when the previous run predates it
  and no site link existed then, site links are a first collection and
  are not reported.

Not covered: changes made only in SYSVOL (GPT.INI version not bumped in
AD) and changes to a GPO's ACL (plugin 11010 does not cover GPOs).

Severity: high when a Tier 0 link is at the domain root or an OU
containing domain controllers; medium otherwise (sites, OUs holding other
Tier 0 objects or accounts). One row per GPO, listing every reason and
scope. Suppressed on a client's first collection run.
"""

PLUGIN = {
    "plugin_id": 11013,
    "category": "Change Detection",
    "name": "GPO Applying to Tier 0 Modified or Newly Linked",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11013",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-CM-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-8.11", "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32", "ISO-27001-2022-A.8.9",
        "SOC2-CC7.2", "SOC2-CC8.1", "SOC2-CC7.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.001",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports Group Policy Objects applying to Tier 0 that changed since the "
        "previous successful collection run: the GPO's versionNumber changed while it "
        "has an enabled link to the domain root, an OU containing domain controllers, "
        "a site, or an OU containing a Tier 0 object or account; or a new (or "
        "re-enabled) link from such a scope to the GPO appeared. A GPO that applies to "
        "domain controllers or administrators is code execution on them. Severity is "
        "high for links at the domain root or a domain-controller OU, medium otherwise. "
        "Only versionNumber is compared, so the schema v38 GPO columns do not produce "
        "findings, and site links are not reported the first time they are collected. "
        "Suppressed on a client's first collection run."
    ),
    "remediation": (
        "Confirm the edit or link against a change record. Security event IDs 5136 "
        "(groupPolicyContainer versionNumber / gPLink modified) and 5137 identify who "
        "made it; Group Policy Management Console (or Get-GPOReport -Guid <guid> "
        "-ReportType Html) shows the current settings -- compare them with a backup "
        "(Backup-GPO) or the AGPM history. Look specifically for new scheduled tasks, "
        "startup/logon scripts, Restricted Groups / Group Policy Preferences local "
        "group changes, user-rights assignments and security-option changes. Revert "
        "unapproved changes with Restore-GPO, or remove the link with Remove-GPLink "
        "-Guid <guid> -Target '<DN>'. Restrict edit rights on Tier 0 GPOs and write "
        "access to gPLink on the domain root and Tier 0 OUs to Tier 0 administrators."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id,
                   COALESCE((
                       SELECT (regexp_match(s2.collector_version, '^([0-9]+)[.]([0-9]+)[.]([0-9]+)'))::int[]
                              >= ARRAY[0, 5, 16]
                       FROM sync_run s2
                       WHERE s2.client_id = %(client_id)s
                         AND s2.run_id < %(run_id)s
                         AND s2.status = 'succeeded'
                       ORDER BY s2.run_id DESC
                       LIMIT 1
                   ), false) AS prior_collected_sites
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        tier0_member_dn AS (
            SELECT lower(o.dn_current) AS dn
            FROM directory_object o
            WHERE o.client_id = %(client_id)s
              AND NOT o.is_deleted
              AND (EXISTS (SELECT 1 FROM v_tier0_object t
                           WHERE t.client_id = o.client_id AND t.object_guid = o.object_guid
                             AND t.tier0_reason NOT IN ('domain_root', 'domain_controller_ou'))
                   OR (o.object_class IN ('user', 'computer')
                       AND EXISTS (SELECT 1 FROM v_privileged_principal pp
                                   WHERE pp.client_id = o.client_id
                                     AND pp.object_guid = o.object_guid)))
        ),
        scope_raw AS (
            SELECT d.object_guid, 1 AS prio, 'domain root' AS scope_kind, true AS high_scope
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            UNION ALL
            SELECT t.object_guid, 2, 'OU containing domain controllers', true
            FROM v_tier0_object t
            WHERE t.client_id = %(client_id)s AND t.tier0_reason = 'domain_controller_ou'
            UNION ALL
            SELECT s.object_guid, 3, 'site', false
            FROM ad_site s
            WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
            UNION ALL
            SELECT ou.object_guid, 4, 'OU containing Tier 0 objects or accounts', false
            FROM ad_ou ou
            JOIN directory_object od
              ON od.object_guid = ou.object_guid AND od.client_id = ou.client_id
            WHERE ou.client_id = %(client_id)s AND ou.valid_to IS NULL
              AND EXISTS (SELECT 1 FROM tier0_member_dn m
                          WHERE right(m.dn, length(od.dn_current) + 1) = ',' || lower(od.dn_current))
        ),
        scope AS (
            SELECT DISTINCT ON (sr.object_guid)
                   sr.object_guid, sr.scope_kind, sr.high_scope, o.dn_current
            FROM scope_raw sr
            JOIN directory_object o
              ON o.object_guid = sr.object_guid AND o.client_id = %(client_id)s
             AND NOT o.is_deleted
            ORDER BY sr.object_guid, sr.prio
        ),
        tier0_link AS (
            SELECT l.gpo_guid, l.container_guid, l.link_enforced, l.run_id_valid_from,
                   l.valid_from, s.scope_kind, s.high_scope, s.dn_current AS scope_dn
            FROM gpo_link_edge l
            JOIN scope s ON s.object_guid = l.container_guid
            WHERE l.client_id = %(client_id)s
              AND l.valid_to IS NULL
              AND l.link_enabled
        ),
        new_link AS (
            SELECT tl.*
            FROM tier0_link tl
            CROSS JOIN prior_run pr
            WHERE pr.prev_run_id IS NOT NULL
              AND tl.run_id_valid_from > pr.prev_run_id
              AND tl.run_id_valid_from <= %(run_id)s
              AND NOT EXISTS (SELECT 1 FROM gpo_link_edge p
                              WHERE p.client_id = %(client_id)s
                                AND p.container_guid = tl.container_guid
                                AND p.gpo_guid = tl.gpo_guid
                                AND p.link_enabled
                                AND p.run_id_valid_from <= pr.prev_run_id
                                AND (p.run_id_valid_to IS NULL OR p.run_id_valid_to > pr.prev_run_id))
              -- site gPLinks collected for the first time are a baseline
              AND (tl.scope_kind <> 'site'
                   OR pr.prior_collected_sites
                   OR EXISTS (SELECT 1 FROM gpo_link_edge p
                              JOIN ad_site st
                                ON st.object_guid = p.container_guid AND st.client_id = p.client_id
                              WHERE p.client_id = %(client_id)s
                                AND p.run_id_valid_from <= pr.prev_run_id
                                AND (p.run_id_valid_to IS NULL OR p.run_id_valid_to > pr.prev_run_id)))
        ),
        modified_gpo AS (
            SELECT g.object_guid, g.version_number, prev.version_number AS prev_version_number,
                   g.valid_from
            FROM ad_gpo g
            CROSS JOIN prior_run pr
            JOIN directory_object_version cv
              ON cv.version_id = g.version_id AND cv.object_guid = g.object_guid
             AND cv.client_id = g.client_id AND cv.valid_from = g.valid_from
            JOIN LATERAL (
                SELECT p.version_number
                FROM ad_gpo p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
                WHERE p.object_guid = g.object_guid
                  AND p.client_id = %(client_id)s
                  AND p.valid_from < g.valid_from
                  AND pv.run_id_valid_from <= pr.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > pr.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
            WHERE g.client_id = %(client_id)s
              AND g.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
              AND prev.version_number IS NOT NULL
              AND g.version_number IS DISTINCT FROM prev.version_number
              AND EXISTS (SELECT 1 FROM tier0_link tl WHERE tl.gpo_guid = g.object_guid)
        ),
        affected AS (
            SELECT gpo_guid FROM new_link
            UNION
            SELECT object_guid FROM modified_gpo
        ),
        per_gpo AS (
            SELECT a.gpo_guid,
                   mg.version_number, mg.prev_version_number, mg.valid_from AS modified_at,
                   (SELECT bool_or(tl.high_scope) FROM tier0_link tl WHERE tl.gpo_guid = a.gpo_guid)
                       AS applies_high,
                   (SELECT string_agg(DISTINCT tl.scope_kind || ' ' || tl.scope_dn, '; '
                                      ORDER BY tl.scope_kind || ' ' || tl.scope_dn)
                      FROM tier0_link tl WHERE tl.gpo_guid = a.gpo_guid) AS all_scopes,
                   (SELECT jsonb_agg(jsonb_build_object(
                               'scope_kind', tl.scope_kind, 'scope_dn', tl.scope_dn,
                               'link_enforced', tl.link_enforced)
                           ORDER BY tl.scope_dn)
                      FROM tier0_link tl WHERE tl.gpo_guid = a.gpo_guid) AS tier0_links,
                   (SELECT string_agg(nl.scope_kind || ' ' || nl.scope_dn, '; '
                                      ORDER BY nl.scope_dn)
                      FROM new_link nl WHERE nl.gpo_guid = a.gpo_guid) AS new_scopes,
                   (SELECT jsonb_agg(jsonb_build_object(
                               'scope_kind', nl.scope_kind, 'scope_dn', nl.scope_dn,
                               'link_enforced', nl.link_enforced,
                               'change_observed_at', nl.valid_from)
                           ORDER BY nl.scope_dn)
                      FROM new_link nl WHERE nl.gpo_guid = a.gpo_guid) AS new_links
            FROM affected a
            LEFT JOIN modified_gpo mg ON mg.object_guid = a.gpo_guid
        )
        SELECT
            'warn' AS status,
            p.gpo_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.applies_high THEN 'high' ELSE 'medium' END AS fd_severity,
            'GPO "' || COALESCE(g.display_name, gdo.dn_current) || '", which applies to Tier 0 ('
                || COALESCE(p.all_scopes, 'no remaining enabled link') || '), '
                || array_to_string(array_remove(ARRAY[
                       CASE WHEN p.prev_version_number IS NOT NULL
                            THEN 'was modified (versionNumber ' || p.prev_version_number || ' -> '
                                 || COALESCE(p.version_number::text, '(not set)') || ')' END,
                       CASE WHEN p.new_scopes IS NOT NULL
                            THEN 'was newly linked to ' || p.new_scopes END
                   ], NULL), ' and ')
                || ' since the previous collection run' AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', gdo.dn_current,
                'gpc_file_sys_path', g.gpc_file_sys_path,
                'gpo_flags', g.gpo_flags,
                'modified', p.prev_version_number IS NOT NULL,
                'version_number', g.version_number,
                'previous_version_number', p.prev_version_number,
                'computer_version', (g.version_number & 65535),
                'user_version', (g.version_number >> 16),
                'new_links', p.new_links,
                'tier0_links', p.tier0_links,
                'applies_to_domain_root_or_dc_ou', p.applies_high,
                'corroborating_event_ids', jsonb_build_array(5136, 5137)
            ) AS detail
        FROM per_gpo p
        JOIN ad_gpo g
          ON g.object_guid = p.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        JOIN directory_object gdo
          ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
         AND NOT gdo.is_deleted
    """,
}
