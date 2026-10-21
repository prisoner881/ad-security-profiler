"""
Plugin 9041: Group Policy Copies Files From Outside the Domain

Reports GPOs whose Group Policy Preferences Files items (Files.xml,
gpo_preference_item_edge preference_type 'Files', sysvol_collector 1.1)
copy a file from a UNC path (fromPath) on a host that is not part of this
domain onto the computers or into the profiles the GPO applies to. Items
with action Delete are ignored.

Hosts are placed as in plugin 1052: the domain's DNS name or any name under
it, its NetBIOS name, or a computer of this domain = the domain (not
reported); another DNS name = outside the domain -- medium: whoever controls
that share decides what lands on every computer the GPO applies to, often an
executable or a script run later (PingCastle T-FileDeployedOutOfDomain); an
IP address or an unknown short name = cannot be placed -- low. A GPO that is
not linked anywhere is low at most.

One row per GPO (object_guid = the GPO) listing each such file. Status 'fail'
at medium. Requires SYSVOL collection (adprofiler.py --sysvol) by
sysvol_collector 1.1 or later.
"""

PLUGIN = {
    "plugin_id": 9041,
    "category": "Organizational Units",
    "name": "Group Policy Copies Files From Outside the Domain",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "GPO-9041",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1484.001",
        "MITRE-ATTCK-T1199",
    ],
    "references": [
        {"title": "PingCastle health check rules (T-FileDeployedOutOfDomain)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
    ],
    "description": (
        "A GPO's Files preference copies a file from a UNC path on a host "
        "outside this domain (medium; low when the GPO is not linked), or on a "
        "host that cannot be placed -- an IP address or an unknown short name "
        "(low). Whoever controls that share decides what is copied to every "
        "computer the GPO applies to."
    ),
    "remediation": (
        "Move the source file to a share in this domain whose permissions only "
        "Tier 0 can change (or the GPO's own SYSVOL folder) and change the "
        "Files item's Source file(s) to it (Group Policy Management Editor > "
        "Preferences > Windows Settings > Files). Delete items that are no "
        "longer needed."
    ),
    "base_severity": "medium",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        dom AS (
            SELECT lower(m.dns_root) AS dns_lc, lower(m.netbios_name) AS nb
            FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
            ORDER BY m.object_guid LIMIT 1
        ),
        known_host AS (
            SELECT lower(rtrim(c.sam_account_name, '$')) AS h
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.sam_account_name IS NOT NULL
            UNION
            SELECT lower(c.dns_hostname)
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.dns_hostname IS NOT NULL
        ),
        linked AS (
            SELECT DISTINCT l.gpo_guid
            FROM gpo_link_edge l
            WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
        ),
        item AS (
            SELECT p.gpo_guid, p.scope, p.item_uid, p.item_name, p.action,
                   btrim(p.details_json::jsonb ->> 'from_path', ' "') AS path,
                   p.details_json::jsonb ->> 'target_path' AS target_path
            FROM gpo_preference_item_edge p
            WHERE p.client_id = %(client_id)s AND p.valid_to IS NULL
              AND p.preference_type = 'Files'
              AND upper(COALESCE(p.action, '')) <> 'D'
              AND (SELECT ok FROM sysvol)
        ),
        placed AS (
            SELECT i.*, h.host,
                   CASE WHEN h.host IS NULL THEN 'local'
                        WHEN h.host = d.dns_lc OR h.host LIKE ('%%.' || d.dns_lc) OR h.host = d.nb
                             OR h.host IN (SELECT kh.h FROM known_host kh) THEN 'domain'
                        WHEN h.host ~ '^[0-9.]+$' OR strpos(h.host, ':') > 0 THEN 'ip'
                        WHEN strpos(h.host, '.') = 0 THEN 'unresolved'
                        ELSE 'outside' END AS place
            FROM item i
            CROSS JOIN dom d
            CROSS JOIN LATERAL (
                SELECT CASE WHEN left(i.path, 2) = repeat(chr(92), 2)
                            THEN NULLIF(lower(split_part(substr(i.path, 3), chr(92), 1)), '') END AS host
            ) h
            WHERE COALESCE(i.path, '') <> ''
        ),
        bad AS (
            SELECT p.*, (lk.gpo_guid IS NOT NULL) AS is_linked
            FROM placed p
            LEFT JOIN linked lk ON lk.gpo_guid = p.gpo_guid
            WHERE p.place IN ('outside', 'ip', 'unresolved')
        )
        SELECT
            CASE WHEN bool_or(b.place = 'outside' AND b.is_linked) THEN 'fail' ELSE 'warn' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(b.place = 'outside' AND b.is_linked) THEN 'medium' ELSE 'low' END AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' copies files from '
                || CASE WHEN bool_or(b.place = 'outside') THEN 'outside the domain'
                        ELSE 'a host that is not a known part of the domain' END
                || CASE WHEN bool_or(b.is_linked) THEN '' ELSE ' (the GPO is not linked)' END || ': '
                || string_agg(b.path || ' -> ' || COALESCE(b.target_path, '?') || ' ('
                              || CASE b.place WHEN 'outside' THEN 'host outside the domain'
                                              WHEN 'ip' THEN 'IP address'
                                              ELSE 'unknown short name' END || ')',
                              '; ' ORDER BY (b.place = 'outside') DESC, lower(b.path), b.item_uid) AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'gpo_linked', bool_or(b.is_linked),
                'files', jsonb_agg(jsonb_build_object('scope', b.scope, 'item', b.item_name,
                                                      'action', b.action, 'from_path', b.path,
                                                      'target_path', b.target_path, 'host', b.host,
                                                      'host_placement', b.place)
                                   ORDER BY (b.place = 'outside') DESC, lower(b.path), b.item_uid),
                'note', 'Hosts are placed by name only; the share''s permissions are not visible.'
            ) AS detail
        FROM bad b
        JOIN ad_gpo g ON g.object_guid = b.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        GROUP BY g.object_guid, g.display_name, g.gpo_guid
    """,
}
