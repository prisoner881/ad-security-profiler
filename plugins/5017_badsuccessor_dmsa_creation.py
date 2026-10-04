"""
Plugin 5017: Principals Can Create Delegated MSAs (BadSuccessor, CVE-2025-53779)

Windows Server 2025 introduced delegated Managed Service Accounts (dMSA,
class msDS-DelegatedManagedServiceAccount). A dMSA "supersedes" an
existing account through msDS-ManagedAccountPrecededByLink, and the KDC
then issues the dMSA tickets carrying the superseded account's
privileges (its SID and group memberships in the PAC). Akamai's
"BadSuccessor" research (May 2025) showed that anyone able to create a
dMSA -- CreateChild on any OU or container -- can set that link to any
account, Domain Admins included, with no rights over the target:
domain compromise from a common, low-looking OU delegation. Microsoft
fixed the core issue in August 2025 (CVE-2025-53779), but creating or
controlling a dMSA remains a Tier 0-relevant right, and the exposure
exists only in a domain with at least one Windows Server 2025 domain
controller.

Findings:
  (a) one row per trustee outside Tier 0 that holds, on an OU or on the
      domain root, an explicit allow ACE granting CreateChild (0x1) with
      no object type (all classes) or with the dMSA class
      (0feb936f-47b3-49f2-9386-1dedc2c23765), or GenericAll / WriteDacl /
      WriteOwner (which give or let the holder grant CreateChild), plus
      non-Tier-0 owners of an OU (an owner can rewrite the DACL). ACEs
      count when they apply to the container itself, or are inherit-only
      and inherited by OUs (they then apply to every child OU).
      critical (fail) when any domain controller runs Windows Server 2025
      (ad_computer.operating_system ILIKE '%2025%'); medium (warn)
      otherwise -- the exposure appears the day a 2025 DC is promoted.
  (b) one row per existing dMSA (ad_computer.is_dmsa, schema v38) whose
      msDS-ManagedAccountPrecededByLink (dmsa_preceded_by) resolves to a
      Tier 0 account (v_privileged_principal / v_tier0_object, built-in
      Administrator or krbtgt, or an adminCount = 1 account) -> critical:
      the dMSA holds (or, once migration completes, will hold) that
      account's privileges. object_guid = the dMSA.

Trustees are "non-Tier-0" by the shared definition: not SYSTEM,
Administrators, Domain Admins, Enterprise Admins, Domain Controllers,
Enterprise Domain Controllers or Creator Owner, not an AdminSDHolder-
protected group (so Account Operators, whose members v_privileged_principal
already counts as Tier 0, is excluded) and not a principal in
v_privileged_principal -- except that, as in 5013/5014, Tier 0 status
derived only from ACLs on / ownership of the domain root or an OU is not
an exemption. Unresolvable SIDs are reported by SID or well-known name.

Caveats: only the domain root and OUs are evaluated; ACLs of plain
containers (CN=Users, CN=Computers, CN=Managed Service Accounts, ...) are
not collected, and CreateChild there is equally sufficient. Inherited
ACEs are reported once, where they are set. operating_system is the
self-reported attribute; a DC that has not yet registered it is missed.
"""

PLUGIN = {
    "plugin_id": 5017,
    "category": "ACLs",
    "name": "Principals Can Create Delegated MSAs (BadSuccessor, CVE-2025-53779)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-5017",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-SI-2",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1078.002",
        "CVE-2025-53779",
    ],
    "references": [
        {"title": "MSRC: CVE-2025-53779 Windows Kerberos Elevation of Privilege Vulnerability",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779"},
        {"title": "NVD: CVE-2025-53779",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-53779"},
    ],
    "description": (
        "Flags principals outside Tier 0 that can create delegated Managed "
        "Service Accounts -- CreateChild (all classes or the dMSA class), "
        "GenericAll, WriteDacl or WriteOwner on an OU or the domain root, or "
        "ownership of an OU -- the BadSuccessor (CVE-2025-53779) path to "
        "inheriting any account's privileges. Critical when a Windows Server "
        "2025 domain controller exists, medium otherwise. Also flags existing "
        "dMSAs whose superseded account (msDS-ManagedAccountPrecededByLink) is "
        "a Tier 0 account (critical)."
    ),
    "remediation": (
        "Install the August 2025 (or later) cumulative update on every "
        "Windows Server 2025 DC (CVE-2025-53779). Remove CreateChild for all "
        "object classes and broad GenericAll/WriteDacl/WriteOwner delegations "
        "on OUs from non-Tier-0 principals, replacing them with class-specific "
        "create rights (e.g. only user or computer objects): `dsacls \"<OU DN>\" "
        "/R <trustee>` then re-grant narrowly, and give OU ownership back to "
        "Domain Admins. For each flagged dMSA, confirm the migration is "
        "legitimate; otherwise clear msDS-ManagedAccountPrecededByLink and "
        "msDS-DelegatedMSAState (`Set-ADServiceAccount <dMSA> -Clear "
        "msDS-ManagedAccountPrecededByLink`) or delete the dMSA, reset the "
        "passwords of the superseded account, and investigate its use."
    ),
    "base_severity": "critical",
    "query": """
        WITH container AS (
            SELECT d.object_guid, o.dn_current, o.owner_sid, 'domain root'::text AS label, true AS is_root
            FROM ad_domain d
            JOIN directory_object o ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            UNION ALL
            SELECT u.object_guid, o.dn_current, o.owner_sid,
                   'OU "' || COALESCE(u.ou_name, o.dn_current) || '"', false
            FROM ad_ou u
            JOIN directory_object o ON o.object_guid = u.object_guid AND o.client_id = u.client_id
                                    AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
        ),
        t0p AS (
            SELECT DISTINCT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
              AND NOT (p.privilege_source IN ('tier0_acl_control', 'tier0_acl_control_via_group',
                                              'tier0_ownership', 'tier0_ownership_via_group')
                       AND p.via_object_guid IN (SELECT object_guid FROM container))
        ),
        tier0_sid AS (
            SELECT d.object_sid AS sid
            FROM t0p JOIN directory_object d
              ON d.object_guid = t0p.object_guid AND d.client_id = %(client_id)s
            WHERE d.object_sid IS NOT NULL
            UNION
            SELECT d.object_sid
            FROM ad_group g
            JOIN directory_object d ON d.object_guid = g.object_guid AND d.client_id = g.client_id
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND g.is_protected_group AND d.object_sid IS NOT NULL
        ),
        dc2025 AS (
            SELECT EXISTS (
                SELECT 1 FROM ad_computer c
                WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
                  AND c.is_domain_controller
                  AND c.operating_system ILIKE '%%2025%%'
            ) AS present
        ),
        grants AS (
            SELECT a.trustee_sid,
                   c.label || CASE WHEN a.inherit_only IS TRUE THEN ' (child OUs)' ELSE '' END AS scope_label,
                   CASE
                       WHEN (a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0
                           THEN 'GenericAll'
                       WHEN (a.access_mask & 1) <> 0 AND a.object_type_guid IS NULL
                           THEN 'CreateChild (all classes)'
                       WHEN (a.access_mask & 1) <> 0
                           THEN 'CreateChild (dMSA)'
                       WHEN (a.access_mask & 262144) <> 0 THEN 'WriteDacl'
                       ELSE 'WriteOwner'
                   END AS right_label
            FROM acl_edge a
            JOIN container c ON c.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherited = FALSE
              AND (a.inherit_only IS NOT TRUE
                   OR a.inherited_object_type_guid IS NULL
                   OR a.inherited_object_type_guid = 'bf967aa5-0de6-11d0-a285-00aa003049e2')
              AND (
                    (a.access_mask & 983551) = 983551
                    OR (a.access_mask & (268435456 | 262144 | 524288)) <> 0
                    OR ((a.access_mask & 1) <> 0
                        AND (a.object_type_guid IS NULL
                             OR a.object_type_guid = '0feb936f-47b3-49f2-9386-1dedc2c23765'))
                  )
            UNION ALL
            SELECT c.owner_sid, c.label, 'Owner'
            FROM container c
            WHERE c.owner_sid IS NOT NULL AND NOT c.is_root
        ),
        filtered AS (
            SELECT g.*
            FROM grants g
            WHERE g.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0')
              AND g.trustee_sid !~ '^S-1-5-21-[0-9-]+-(512|516|519)$'
              AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = g.trustee_sid)
        ),
        per_scope AS (
            SELECT f.trustee_sid, f.scope_label,
                   string_agg(DISTINCT f.right_label, ', ' ORDER BY f.right_label) AS rights
            FROM filtered f
            GROUP BY f.trustee_sid, f.scope_label
        ),
        per_trustee AS (
            SELECT ps.trustee_sid,
                   string_agg(ps.rights || ' on ' || ps.scope_label, '; ' ORDER BY ps.scope_label) AS grant_list,
                   jsonb_agg(jsonb_build_object('scope', ps.scope_label, 'rights', ps.rights)
                             ORDER BY ps.scope_label) AS grants
            FROM per_scope ps
            GROUP BY ps.trustee_sid
        ),
        dmsa AS (
            SELECT c.object_guid, c.sam_account_name, c.dmsa_preceded_by, c.dmsa_state,
                   tgt.object_guid AS target_guid, tgt.sam_account_name AS target_sam,
                   tgt.object_sid AS target_sid
            FROM ad_computer c
            JOIN directory_object co
              ON co.object_guid = c.object_guid AND co.client_id = c.client_id AND NOT co.is_deleted
            JOIN directory_object tgt
              ON tgt.client_id = c.client_id AND NOT tgt.is_deleted
             AND lower(tgt.dn_current) = lower(c.dmsa_preceded_by)
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_dmsa
              AND c.dmsa_preceded_by IS NOT NULL
        )
        -- (a) principals that can create dMSAs
        SELECT
            CASE WHEN dc.present THEN 'fail' ELSE 'warn' END AS status,
            tdo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN dc.present THEN 'critical' ELSE 'medium' END AS fd_severity,
            'Principal ' || COALESCE(tdo.sam_account_name, wk.name, pt.trustee_sid)
                || ' can create delegated MSAs (BadSuccessor, CVE-2025-53779): ' || pt.grant_list
                || CASE WHEN dc.present THEN ' -- a Windows Server 2025 domain controller is present'
                        ELSE ' -- exploitable once a Windows Server 2025 domain controller is added' END
                AS summary,
            jsonb_build_object(
                'trustee_sid', pt.trustee_sid,
                'sam_account_name', tdo.sam_account_name,
                'object_class', tdo.object_class,
                'grants', pt.grants,
                'windows_server_2025_dc_present', dc.present
            ) AS detail
        FROM per_trustee pt
        CROSS JOIN dc2025 dc
        LEFT JOIN LATERAL (
            SELECT d.object_guid, d.sam_account_name, d.object_class
            FROM directory_object d
            WHERE d.client_id = %(client_id)s AND d.object_sid = pt.trustee_sid
              AND NOT d.is_deleted
            ORDER BY d.object_guid
            LIMIT 1
        ) tdo ON TRUE
        LEFT JOIN (VALUES
            ('S-1-1-0', 'Everyone'), ('S-1-5-7', 'Anonymous Logon'),
            ('S-1-5-11', 'Authenticated Users'), ('S-1-5-32-545', 'Users'),
            ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
        ) AS wk(sid, name) ON wk.sid = pt.trustee_sid

        UNION ALL

        -- (b) existing dMSAs superseding a Tier 0 account
        SELECT
            'fail',
            m.object_guid,
            NULL, NULL, NULL, NULL,
            'critical',
            'dMSA ' || COALESCE(m.sam_account_name, m.object_guid::text)
                || ' supersedes Tier 0 account ' || COALESCE(m.target_sam, m.dmsa_preceded_by)
                || ' (msDS-ManagedAccountPrecededByLink) and inherits its privileges',
            jsonb_build_object(
                'sam_account_name', m.sam_account_name,
                'preceded_by_dn', m.dmsa_preceded_by,
                'preceded_by_sid', m.target_sid,
                'dmsa_state', m.dmsa_state
            )
        FROM dmsa m
        WHERE m.target_sid ~ '^S-1-5-21-[0-9-]+-(500|502)$'
           OR EXISTS (SELECT 1 FROM v_privileged_principal p
                      WHERE p.client_id = %(client_id)s AND p.object_guid = m.target_guid)
           OR EXISTS (SELECT 1 FROM v_tier0_object t
                      WHERE t.client_id = %(client_id)s AND t.object_guid = m.target_guid)
           OR EXISTS (SELECT 1 FROM ad_user u
                      WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
                        AND u.object_guid = m.target_guid AND u.admin_count = 1)
           OR EXISTS (SELECT 1 FROM ad_computer cc
                      WHERE cc.client_id = %(client_id)s AND cc.valid_to IS NULL
                        AND cc.object_guid = m.target_guid AND cc.admin_count = 1)
    """,
}
