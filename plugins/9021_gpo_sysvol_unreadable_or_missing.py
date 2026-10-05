"""
Plugin 9021: GPO Folder Could Not Be Read or Is Missing from SYSVOL

Reports GPOs whose SYSVOL folder (the Group Policy Template, GPT) could not
be evaluated at the last SYSVOL collection, from ad_gpo_sysvol.read_status:

- 'not_found': the GPO object exists in Active Directory (the Group Policy
  Container, GPC) but its folder is missing from SYSVOL -- an orphaned GPC,
  usually left by a failed deletion, a restore of the AD object without its
  files, or broken SYSVOL replication (DFSR/FRS). Clients that apply it log
  Group Policy errors (event 1058 / 1096) and skip it. status fail, low.
- 'access_denied' / 'error': the collection account could not read the
  folder -- typically because the GPO's security filtering removed
  Authenticated Users' read permission, or a transient SMB error. The
  GPO's content (and anything risky in it) was not evaluated by the SYSVOL
  plugins; previously collected settings, if any, are kept. status warn,
  info: grant the collection account read, or ignore if the filtering is
  intentional.

Why: findings from plugins 9008-9023 are only as complete as the GPO
folders they could read; a "setting absent" conclusion for a domain
controller is uncertain when a GPO that applies to it is in this list.

One row per GPO (object_guid = GPO). Deleted GPOs are excluded. Zero rows
unless SYSVOL has been collected (at least one GPO folder read
successfully; adprofiler.py --sysvol). ad_gpo_sysvol reflects the latest
SYSVOL collection, which may be older than the latest LDAP run.
"""

PLUGIN = {
    "plugin_id": 9021,
    "category": "Organizational Units",
    "name": "GPO Folder Could Not Be Read or Is Missing from SYSVOL",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9021",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-800-53-CM-2", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
    ],
    "references": [],
    "description": (
        "Reports GPOs whose SYSVOL folder could not be evaluated at the last SYSVOL "
        "collection. A missing folder (GPO object in AD with no SYSVOL folder, an orphaned "
        "GPC) is a fail at low severity: the GPO cannot apply and usually points to a "
        "failed deletion or broken SYSVOL replication. A folder the collection account "
        "could not read (access denied or another error) is a warning at info severity: "
        "the GPO's settings were not evaluated, so SYSVOL-based findings may be "
        "incomplete. One row per GPO. Requires SYSVOL collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Orphaned GPC (folder missing): check SYSVOL replication health (dfsrdiag "
        "ReplicationState, or 'Get-GPO -All' compared with the folders under "
        "\\\\<domain>\\SYSVOL\\<domain>\\Policies). If the GPO is still needed, restore "
        "it from a backup (Restore-GPO) or authoritative SYSVOL restore; otherwise delete "
        "the GPO object (Remove-GPO) and its links. Unreadable folder: if the GPO is "
        "security-filtered on purpose, give the collection account (or a group containing "
        "it) Read on the GPO (Group Policy Management > Delegation > Add, Read), which "
        "does not make the GPO apply to it; or accept that the GPO is not assessed. For "
        "other errors, re-run the collection and check the error detail."
    ),
    "base_severity": "low",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        )
        SELECT
            CASE WHEN s.read_status = 'not_found' THEN 'fail' ELSE 'warn' END AS status,
            s.gpo_object_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.read_status = 'not_found' THEN 'low' ELSE 'info' END AS fd_severity,
            CASE WHEN s.read_status = 'not_found'
                 THEN 'GPO "' || COALESCE(g.display_name, d.dn_current)
                      || '" has no folder on SYSVOL (orphaned GPC: GPO object in AD with no SYSVOL folder)'
                 ELSE 'Group Policy content of GPO "' || COALESCE(g.display_name, d.dn_current)
                      || '" was not evaluated (SYSVOL folder '
                      || CASE WHEN s.read_status = 'access_denied' THEN 'access denied' ELSE 'read error' END
                      || '); grant the collection account read, or ignore if intentionally filtered'
            END AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', d.dn_current,
                'read_status', s.read_status,
                'sysvol_path', s.sysvol_path,
                'gpc_file_sys_path', g.gpc_file_sys_path,
                'error_detail', s.error_detail,
                'sysvol_run_id', s.run_id,
                'collected_at', s.collected_at,
                'has_enabled_link', EXISTS (
                    SELECT 1 FROM gpo_link_edge l
                    WHERE l.client_id = %(client_id)s AND l.gpo_guid = s.gpo_object_guid
                      AND l.valid_to IS NULL AND l.link_enabled),
                'applies_to_domain_controller', EXISTS (
                    SELECT 1 FROM v_gpo_dc_application a
                    WHERE a.client_id = %(client_id)s AND a.gpo_guid = s.gpo_object_guid
                      AND a.precedence IS NOT NULL)
            ) AS detail
        FROM ad_gpo_sysvol s
        CROSS JOIN sysvol sv
        JOIN directory_object d
          ON d.object_guid = s.gpo_object_guid AND d.client_id = s.client_id AND NOT d.is_deleted
        LEFT JOIN ad_gpo g
          ON g.object_guid = s.gpo_object_guid AND g.client_id = s.client_id AND g.valid_to IS NULL
        WHERE sv.collected
          AND s.client_id = %(client_id)s
          AND s.read_status IN ('not_found', 'access_denied', 'error')
    """,
}
