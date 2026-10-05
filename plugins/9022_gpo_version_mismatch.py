"""
Plugin 9022: GPO Version Differs Between AD and SYSVOL

Reports GPOs whose version in Active Directory (groupPolicyContainer
versionNumber, ad_gpo.version_number) differs from the version in the
GPO's SYSVOL gpt.ini ([General] Version, ad_gpo_sysvol.gpt_ini_version).

Why: Group Policy clients compare these numbers to decide whether a GPO
changed; GPMC bumps both on every edit. A difference means the two halves
of the GPO are out of step: SYSVOL (DFSR/FRS) or AD replication between
DCs is broken or lagging, or the GPO was edited outside GPMC (files
written directly to SYSVOL, or versionNumber set in AD). Clients may then
apply stale settings or skip the GPO, and an out-of-band edit of SYSVOL
is also a tampering technique (MITRE ATT&CK T1484.001).

Caveat: SYSVOL replication lags AD replication, so a GPO edited minutes
before collection can mismatch transiently; a mismatch that persists
across runs is the real signal. The collector reads SYSVOL from one DC
and LDAP from one DC, which may differ.

Comparison: only GPOs read successfully (read_status 'ok') with both
numbers present. The AD version compared is the one current at the run
of the last SYSVOL collection (ad_gpo_sysvol.run_id), so a later LDAP-only
run does not create a false mismatch. One row per GPO, status warn, low.
Zero rows unless SYSVOL has been collected (adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9022,
    "category": "Organizational Units",
    "name": "GPO Version Differs Between AD and SYSVOL",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9022",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-800-53-CM-2", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "MITRE-ATTCK-T1484.001",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
    ],
    "description": (
        "Reports GPOs whose version number in Active Directory differs from the version "
        "in their SYSVOL gpt.ini. A persistent mismatch means broken SYSVOL or AD "
        "replication, or a GPO edited outside Group Policy Management (directly on SYSVOL "
        "or in AD); clients may apply stale settings. SYSVOL replication lag can cause a "
        "transient mismatch right after an edit, so confirm it persists. One row per GPO. "
        "Requires SYSVOL collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Re-run the collection after replication has had time to converge. If the "
        "mismatch persists, check SYSVOL replication (dfsrdiag ReplicationState, DFS "
        "Replication event log; 'repadmin /replsummary' for AD) and compare the GPO on "
        "each DC (Group Policy Management > the GPO > Status tab, 'Detect Now'). If "
        "replication is healthy, find out who changed the GPO outside GPMC (event 5136 on "
        "the GPC, file auditing on SYSVOL), review its settings, and re-save it in GPMC "
        "(any edit increments both versions) or restore it from a backup (Restore-GPO)."
    ),
    "base_severity": "low",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        cmp AS (
            SELECT s.gpo_object_guid, s.gpt_ini_version, s.sysvol_path, s.run_id AS sysvol_run_id,
                   s.collected_at,
                   (SELECT p.version_number
                      FROM ad_gpo p
                      JOIN directory_object_version pv
                        ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                       AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
                     WHERE p.client_id = %(client_id)s
                       AND p.object_guid = s.gpo_object_guid
                       AND pv.run_id_valid_from <= s.run_id
                       AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > s.run_id)
                     ORDER BY p.valid_from DESC
                     LIMIT 1) AS ad_version
            FROM ad_gpo_sysvol s
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND s.client_id = %(client_id)s
              AND s.read_status = 'ok'
              AND s.gpt_ini_version IS NOT NULL
        )
        SELECT
            'warn' AS status,
            c.gpo_object_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'GPO "' || COALESCE(g.display_name, d.dn_current) || '" version differs between AD ('
                || c.ad_version || ') and SYSVOL gpt.ini (' || c.gpt_ini_version || ')' AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', d.dn_current,
                'ad_version_number', c.ad_version,
                'ad_computer_version', (c.ad_version & 65535),
                'ad_user_version', (c.ad_version >> 16),
                'gpt_ini_version', c.gpt_ini_version,
                'gpt_computer_version', (c.gpt_ini_version & 65535),
                'gpt_user_version', (c.gpt_ini_version >> 16),
                'sysvol_path', c.sysvol_path,
                'sysvol_run_id', c.sysvol_run_id,
                'collected_at', c.collected_at,
                'current_ad_version_number', g.version_number,
                'caveat', 'SYSVOL replication lag can cause a transient mismatch; a persistent one means broken replication or an edit outside GPMC'
            ) AS detail
        FROM cmp c
        JOIN directory_object d
          ON d.object_guid = c.gpo_object_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        LEFT JOIN ad_gpo g
          ON g.object_guid = c.gpo_object_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        WHERE c.ad_version IS NOT NULL
          AND c.ad_version <> c.gpt_ini_version
    """,
}
