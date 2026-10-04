"""
Plugin 2038: Non-Tier-0 Principals Can Read LAPS Passwords

Detects explicit allow ACEs on OUs and on the domain root that let a
principal outside Tier 0 read the LAPS-managed local administrator
password of computers below that OU/domain root. An ACE counts when it
reaches computer objects (inherited_object_type_guid NULL or the
computer class bf967a86-0de6-11d0-a285-00aa003049e2) and grants one of:
  - CONTROL_ACCESS (0x100) or READ_PROP (0x10) on a LAPS password
    attribute -- ms-Mcs-AdmPwd (legacy LAPS), msLAPS-Password,
    msLAPS-EncryptedPassword or msLAPS-EncryptedDSRMPassword (Windows
    LAPS) -- matched on the schemaIDGUIDs in ad_domain.laps_attribute_guids;
  - All Extended Rights (CONTROL_ACCESS with no object type);
  - GenericAll (Full Control).
"Read all properties" (READ_PROP with no object type) is NOT counted:
the LAPS password attributes are confidential and need CONTROL_ACCESS,
which a plain generic read never grants.

Why it matters: the LAPS password is the local Administrator password of
the computer. Whoever can read it controls the machine and every
credential cached on it (BloodHound's ReadLAPSPassword edge; Microsoft's
LAPS guidance limits readers to the specific admin groups that need
them). Delegations that were meant for a help desk often end up granted
to broad groups, at the domain root, or to accounts that were never
reviewed -- and on servers that is lateral movement to where Tier 0
credentials tend to be.

Scope and exclusions:
  - Only OUs / the domain root containing at least one enabled computer
    (DN suffix match on directory_object.dn_current) are evaluated.
  - Only explicit (non-inherited) ACEs: an inherited copy on a child OU
    is the same grant, already reported where it is defined (every OU and
    the domain root are collected). A child OU that blocks DACL
    inheritance is not taken into account, so a grant may reach fewer
    computers than reported.
  - Excluded trustees: Tier 0 principals (v_privileged_principal,
    AdminSDHolder-protected groups) and the default holders SYSTEM,
    Domain Admins, Enterprise Admins, Administrators, Domain Controllers,
    Enterprise Domain Controllers and SELF (the computer reading its own
    password).
  - Unresolvable trustee SIDs (not in directory_object) are still
    reported, by SID (object_guid NULL).

Data caveats: acl_edge does not record whether an ACE is inheritable at
all, so a non-inherit-only ACE scoped to all classes that applies only
to the OU object itself is counted as reaching its computers. The
collector merges ACEs that differ only in inherited_object_type_guid
into one edge with that column NULL (see plugin 5010). If
ad_domain.laps_attribute_guids is NULL/empty (pre-v38 collection, or no
LAPS schema), only the All-Extended-Rights / GenericAll part can be
evaluated; detail.laps_attribute_guids_available says so.

One row per trustee, aggregating every OU/domain-root scope. high if
any reached computer is a server or DC (operating_system ILIKE
'%server%' or is_domain_controller), medium otherwise (workstations
only).
"""

PLUGIN = {
    "plugin_id": 2038,
    "category": "Computer Accounts",
    "name": "Non-Tier-0 Principals Can Read LAPS Passwords",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-2038",
    "framework_tags": [
        "MITRE-ATTCK-T1552",
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01", "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-3.11", "ISO-27001-2022-A.5.17", "SOC2-CC6.1",
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3", "ISO-27001-2022-A.8.3", "SOC2-CC6.3",
    ],
    "references": [
        {"title": "Microsoft: Windows LAPS overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"},
        {"title": "BloodHound: ReadLAPSPassword edge",
         "url": "https://bloodhound.specterops.io/resources/edges/read-laps-password"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "Flags principals outside Tier 0 that hold, on an OU or the domain root "
        "containing enabled computers, an ACE letting them read LAPS-managed local "
        "administrator passwords: read/extended right on ms-Mcs-AdmPwd, "
        "msLAPS-Password, msLAPS-EncryptedPassword or msLAPS-EncryptedDSRMPassword, "
        "All Extended Rights, or GenericAll. High when servers or DCs are in reach, "
        "medium for workstation-only scopes."
    ),
    "remediation": (
        "Review each trustee and scope in the evidence. Remove grants that are not "
        "needed, and replace broad ones (All Extended Rights, Full Control, rights "
        "at the domain root, broad groups) with a narrowly scoped read right for a "
        "dedicated admin group on the OU that holds the computers it manages: "
        "Windows LAPS: `Set-LapsADReadPasswordPermission -Identity \"OU=...\" "
        "-AllowedPrincipals <group>`, check with `Find-LapsADExtendedRights "
        "-Identity \"OU=...\"`; legacy LAPS: `Set-AdmPwdReadPasswordPermission` / "
        "`Find-AdmPwdExtendedRights`. Remove unwanted ACEs with dsacls or ADSI Edit. "
        "Keep server and workstation computers in separate OUs with separate "
        "reader groups."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            SELECT d.object_guid, d.laps_attribute_guids
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        laps_guid AS (
            SELECT DISTINCT kv.key AS attr, lower(btrim(kv.value)) AS guid_lc
            FROM dom
            CROSS JOIN LATERAL jsonb_each_text(
                CASE WHEN jsonb_typeof(dom.laps_attribute_guids) = 'object'
                     THEN dom.laps_attribute_guids ELSE '{}'::jsonb END) kv
            WHERE kv.key IN ('ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword',
                             'msLAPS-EncryptedDSRMPassword')
              AND NULLIF(btrim(kv.value), '') IS NOT NULL
        ),
        scope AS (
            SELECT o.object_guid, o.dn_current
            FROM directory_object o
            WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
              AND (o.object_guid IN (SELECT object_guid FROM dom)
                   OR o.object_guid IN (SELECT ou.object_guid FROM ad_ou ou
                                         WHERE ou.client_id = %(client_id)s AND ou.valid_to IS NULL))
        ),
        enabled_computer AS (
            SELECT lower(cd.dn_current) AS dn_lc,
                   (c.is_domain_controller OR c.operating_system ILIKE '%%server%%') AS is_server,
                   (c.laps_expiration_legacy IS NOT NULL OR c.laps_expiration_modern IS NOT NULL) AS laps_managed
            FROM ad_computer c
            JOIN directory_object cd
              ON cd.object_guid = c.object_guid AND cd.client_id = c.client_id AND NOT cd.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_enabled IS TRUE
        ),
        scope_reach AS (
            SELECT s.object_guid, s.dn_current,
                   count(*) AS computer_count,
                   count(*) FILTER (WHERE ec.is_server) AS server_count,
                   count(*) FILTER (WHERE ec.laps_managed) AS laps_managed_count
            FROM scope s
            JOIN enabled_computer ec
              ON right(ec.dn_lc, length(s.dn_current) + 1) = ',' || lower(s.dn_current)
            GROUP BY s.object_guid, s.dn_current
        ),
        grant_ace AS (
            SELECT a.trustee_sid, sr.object_guid AS scope_guid, sr.dn_current AS scope_dn,
                   sr.computer_count, sr.server_count, sr.laps_managed_count,
                   CASE
                       WHEN a.object_type_guid IS NULL
                        AND ((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0)
                           THEN 'GenericAll'
                       WHEN a.object_type_guid IS NULL AND (a.access_mask & 256) <> 0
                           THEN 'All Extended Rights'
                       ELSE 'Read ' || lg.attr
                   END AS right_label
            FROM acl_edge a
            JOIN scope_reach sr ON sr.object_guid = a.object_guid
            LEFT JOIN laps_guid lg ON lg.guid_lc = lower(a.object_type_guid::text)
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherited IS NOT TRUE
              AND (a.inherited_object_type_guid IS NULL
                   OR a.inherited_object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2')
              AND (
                    (a.object_type_guid IS NULL
                     AND ((a.access_mask & 983551) = 983551
                          OR (a.access_mask & 268435456) <> 0
                          OR (a.access_mask & 256) <> 0))
                 OR (lg.attr IS NOT NULL AND (a.access_mask & (256 | 16)) <> 0)
              )
              -- default holders
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-9', 'S-1-5-10', 'S-1-5-32-544')
              AND a.trustee_sid NOT LIKE 'S-1-5-21-%%-512'
              AND a.trustee_sid NOT LIKE 'S-1-5-21-%%-519'
              AND a.trustee_sid NOT LIKE 'S-1-5-21-%%-516'
        ),
        tier0 AS (
            SELECT p.object_guid FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
            UNION
            SELECT g.object_guid FROM ad_group g
             WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_protected_group
        ),
        resolved AS (
            SELECT ga.*, t.object_guid AS trustee_guid, t.sam_account_name AS trustee_name,
                   t.object_class::text AS trustee_class
            FROM grant_ace ga
            LEFT JOIN directory_object t
              ON t.object_sid = ga.trustee_sid AND t.client_id = %(client_id)s AND NOT t.is_deleted
            WHERE t.object_guid IS NULL
               OR t.object_guid NOT IN (SELECT object_guid FROM tier0)
        ),
        per_scope AS (
            SELECT r.trustee_sid, r.trustee_guid, r.trustee_name, r.trustee_class,
                   r.scope_guid, r.scope_dn, r.computer_count, r.server_count, r.laps_managed_count,
                   string_agg(DISTINCT r.right_label, ', ' ORDER BY r.right_label) AS rights
            FROM resolved r
            GROUP BY r.trustee_sid, r.trustee_guid, r.trustee_name, r.trustee_class,
                     r.scope_guid, r.scope_dn, r.computer_count, r.server_count, r.laps_managed_count
        ),
        avail AS (
            SELECT EXISTS (SELECT 1 FROM laps_guid) AS has_guids
        )
        SELECT
            CASE WHEN sum(ps.server_count) > 0 THEN 'fail' ELSE 'warn' END AS status,
            ps.trustee_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN sum(ps.server_count) > 0 THEN 'high' ELSE 'medium' END AS fd_severity,
            COALESCE(ps.trustee_name,
                     CASE ps.trustee_sid WHEN 'S-1-1-0' THEN 'Everyone'
                                         WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                         WHEN 'S-1-5-7' THEN 'Anonymous Logon'
                                         WHEN 'S-1-3-0' THEN 'Creator Owner'
                                         ELSE ps.trustee_sid END)
                || ' can read LAPS passwords ('
                || (SELECT string_agg(DISTINCT x, ', ' ORDER BY x)
                      FROM unnest(string_to_array(string_agg(ps.rights, ', '), ', ')) x)
                || ') of computers in ' || count(*) || ' OU/domain scope(s)'
                || CASE WHEN sum(ps.server_count) > 0 THEN ', including servers or domain controllers'
                        ELSE ' (workstations only)' END AS summary,
            jsonb_build_object(
                'trustee_sid', ps.trustee_sid,
                'trustee_name', ps.trustee_name,
                'trustee_class', ps.trustee_class,
                'trustee_resolved', ps.trustee_guid IS NOT NULL,
                'scopes', jsonb_agg(jsonb_build_object(
                    'dn', ps.scope_dn,
                    'rights', ps.rights,
                    'enabled_computers', ps.computer_count,
                    'servers_or_dcs', ps.server_count,
                    'laps_managed_computers', ps.laps_managed_count
                ) ORDER BY ps.scope_dn),
                'laps_attribute_guids_available', bool_and(av.has_guids),
                'note', CASE WHEN bool_and(av.has_guids) THEN NULL
                             ELSE 'ad_domain.laps_attribute_guids is empty: only All Extended Rights '
                                  '/ GenericAll grants were evaluated; attribute-specific LAPS read '
                                  'grants could not be checked' END
            ) AS detail
        FROM per_scope ps
        CROSS JOIN avail av
        GROUP BY ps.trustee_sid, ps.trustee_guid, ps.trustee_name, ps.trustee_class
        ORDER BY ps.trustee_sid
    """,
}
