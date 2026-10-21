"""
Plugin 5018: Dangerous Extended Rights Delegated on the Domain or an OU

Reports allow ACEs granting one of three dangerous extended rights
(CONTROL_ACCESS with the right's rightsGuid) to a principal that is not
Tier 0:

  Migrate-SID-History   ba33815a-4f93-4c76-87f3-57574bff8109
      lets the holder write sIDHistory on objects (SID-history injection:
      any SID, Domain Admins or Enterprise Admins included, can be added to
      an account it controls -- MITRE ATT&CK T1134.005).
  Unexpire-Password     ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501
      lets the holder restore an expired password, defeating password
      expiry for accounts it controls. It also needs write access to the
      target's pwdLastSet, so it is rated low. Windows grants it to
      Authenticated Users on the domain root by default; that ACE is not
      reported.
  Reanimate-Tombstones  45ec5156-db7e-47bb-b53f-dbeb2d03c40f
      lets the holder restore deleted objects -- including deleted
      privileged accounts with their group memberships. Checked on OUs
      here; on the domain root it is plugin 5008.

Checked on the domain root (every ACE) and on each OU (explicit ACEs only,
so a grant inherited from the domain is reported once). One row per object
(object_guid = the domain or the OU), listing each trustee and right
(PingCastle P-DangerousExtendedRight).

Tier 0 (never reported): SYSTEM, Administrators, Enterprise Domain
Controllers, Domain Admins (-512), Domain Controllers (-516), Schema Admins
(-518), Enterprise Admins (-519), and any principal in
v_privileged_principal. A trustee SID that resolves to no collected object
is reported as an orphaned or unresolved SID.

Severity: high when Migrate-SID-History is granted (critical when to a broad
principal: Everyone, Authenticated Users, Domain Users, Domain Computers,
Users); Reanimate-Tombstones medium (high when to a broad principal);
Unexpire-Password low (medium when to a broad principal).
"""

PLUGIN = {
    "plugin_id": 5018,
    "category": "ACLs",
    "name": "Dangerous Extended Rights Delegated on the Domain or an OU",
    "version": "1.1",
    "revision_date": "2026-10-21",
    "control_id": "ACL-5018",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1134.005",
        "MITRE-ATTCK-T1222.001",
    ],
    "references": [
        {"title": "Microsoft: Control access rights (Migrate-SID-History, Unexpire-Password, Reanimate-Tombstones)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/control-access-rights"},
        {"title": "PingCastle health check rules (P-DangerousExtendedRight)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1134.005: SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
    ],
    "description": (
        "A non-Tier 0 principal holds the Migrate-SID-History, "
        "Unexpire-Password or Reanimate-Tombstones extended right on the "
        "domain root or an OU. Migrate-SID-History allows SID-history "
        "injection (high; critical for a broad group); Reanimate-Tombstones "
        "is medium (high for a broad group); Unexpire-Password is low "
        "(medium for a broad group; the Windows default grant to "
        "Authenticated Users on the domain root is not reported)."
    ),
    "remediation": (
        "Remove the extended right from the trustee (dsacls <DN> /R "
        "<trustee> removes all its ACEs; or edit the Advanced Security "
        "settings of the domain or OU and delete the 'Migrate SID History', "
        "'Unexpire Password' or 'Reanimate Tombstones' entry). These rights "
        "are only needed temporarily, by Tier 0 administrators, during a "
        "domain migration or a recovery."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            SELECT d.object_sid::text AS dsid
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL AND d.object_sid IS NOT NULL
            ORDER BY d.object_guid LIMIT 1
        ),
        target AS (
            SELECT o.object_guid, o.object_class::text AS kind, o.dn_current
            FROM directory_object o
            WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
              AND o.object_class IN ('domain', 'ou')
        ),
        rights (guid, right_name, rank) AS (
            VALUES ('ba33815a-4f93-4c76-87f3-57574bff8109', 'Migrate-SID-History', 3),
                   ('ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501', 'Unexpire-Password', 1),
                   ('45ec5156-db7e-47bb-b53f-dbeb2d03c40f', 'Reanimate-Tombstones', 2)
        ),
        ace AS (
            SELECT DISTINCT t.object_guid, t.kind, t.dn_current, a.trustee_sid::text AS sid,
                   r.right_name, r.rank
            FROM acl_edge a
            JOIN target t ON t.object_guid = a.object_guid
            JOIN rights r ON lower(a.object_type_guid::text) = r.guid
            WHERE a.client_id = %(client_id)s AND a.valid_to IS NULL
              AND a.ace_type = 'allow' AND a.inherit_only IS NOT TRUE
              AND (a.access_mask & 256) <> 0
              AND (t.kind = 'domain' OR a.inherited IS NOT TRUE)
              AND NOT (t.kind = 'domain' AND r.right_name = 'Reanimate-Tombstones')
              -- Windows default on the domain root
              AND NOT (t.kind = 'domain' AND r.right_name = 'Unexpire-Password'
                       AND a.trustee_sid::text = 'S-1-5-11')
        ),
        labelled AS (
            SELECT x.*,
                   COALESCE(p.sam_account_name,
                            CASE x.sid WHEN 'S-1-1-0' THEN 'Everyone' WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                       WHEN 'S-1-5-7' THEN 'Anonymous Logon' WHEN 'S-1-5-32-545' THEN 'Users' END,
                            CASE WHEN x.sid LIKE (SELECT dsid FROM dom) || '-%%' THEN 'orphaned SID ' || x.sid
                                 ELSE 'unresolved SID ' || x.sid END) AS trustee,
                   (x.sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545')
                    OR x.sid ~ '^S-1-5-21-[0-9-]+-(513|515)$') AS broad
            FROM ace x
            LEFT JOIN directory_object p
              ON p.object_sid = x.sid AND p.client_id = %(client_id)s AND NOT p.is_deleted
            WHERE x.sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9')
              AND x.sid !~ '-(512|516|518|519)$'
              AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                              WHERE vp.client_id = %(client_id)s AND vp.object_guid = p.object_guid)
        ),
        graded AS (
            SELECT l.*,
                   CASE WHEN l.rank = 3 AND l.broad THEN 4 WHEN l.rank = 3 THEN 3
                        WHEN l.broad THEN l.rank + 1 ELSE l.rank END AS sev
            FROM labelled l
        )
        SELECT
            CASE WHEN max(g.sev) >= 3 THEN 'fail' ELSE 'warn' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(g.sev) WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium'
                            ELSE 'low' END AS fd_severity,
            CASE WHEN g.kind = 'domain' THEN 'The domain root' ELSE 'OU ' || g.dn_current END
                || ' delegates dangerous extended rights to non-Tier 0 principals: '
                || string_agg(g.trustee || ' (' || g.right_name || ')', ', '
                              ORDER BY lower(g.trustee), g.right_name) AS summary,
            jsonb_build_object(
                'object_kind', g.kind,
                'distinguished_name', g.dn_current,
                'grants', jsonb_agg(jsonb_build_object('trustee', g.trustee, 'trustee_sid', g.sid,
                                                       'right', g.right_name, 'broad_principal', g.broad)
                                    ORDER BY lower(g.trustee), g.right_name)
            ) AS detail
        FROM graded g
        GROUP BY g.object_guid, g.kind, g.dn_current
    """,
}
