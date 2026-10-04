"""
Plugin 5013: Non-Tier-0 Principals Can Link GPOs to the Domain or Tier 0 OUs

Detects property-scoped allow ACEs on the domain root or on OUs that
grant WRITE_PROP (0x20) on gPLink (f30e3bbe-9ff0-11d1-b603-0000f80367c1)
or gPOptions (f30e3bbf-9ff0-11d1-b603-0000f80367c1) to principals
outside Tier 0. Write gPLink lets the holder link any GPO -- including
one they created or can edit -- to that container, so its settings
(scheduled tasks, scripts, local group membership) run on every user and
computer below it; write gPOptions lets them set Block Inheritance,
stripping the domain's security baseline GPOs from the OU. These are the
"Link GPOs" / "Manage Group Policy links" delegations (BloodHound
WriteGPLink edge, PingCastle, ANSSI). Plugins 5003, 5010 and 9001 only
look at generic rights (GenericAll/GenericWrite/WriteDacl/WriteOwner),
so these narrow grants were invisible.

Scope: explicit (non-inherited) ACEs on the domain root and on each OU
that either apply to the object itself (not inherit-only) or are
inherit-only and inherited by OUs (inherited object type empty or
organizationalUnit) -- the latter reach every child OU. An ACE inherited
from a parent is reported once, where it is set.

Severity: critical when the scope is the domain root, an OU containing a
domain controller (the Domain Controllers OU or any OU above a DC), or
an OU containing any Tier 0 object (v_tier0_object) or Tier 0 principal
(v_privileged_principal) anywhere below it; high otherwise. One row per
trustee, listing every scope.

Excluded trustees: SYSTEM, Administrators, Domain Admins, Enterprise
Admins, Domain Controllers, Enterprise Domain Controllers, Creator Owner,
Self, AdminSDHolder-protected groups, and Tier 0 principals
(v_privileged_principal). Tier 0 status that v_privileged_principal
derives from an ACL or ownership of the domain root or an OU
(privilege_source tier0_acl_control / tier0_ownership, with or without
_via_group, via the domain root or an OU) is NOT treated as an
exemption, nor does it make an OU "contain Tier 0" (DCSync and
protected-group membership still do): write gPLink on the domain root or the DC OU is
itself one of the ways the view classifies a principal as Tier 0, so
honouring it would hide exactly the grants this plugin reports (and
generic rights there are findings of 5003/5010/9001). Unresolvable
trustee SIDs are reported by SID or well-known name.

Caveats: linking a GPO also requires being able to read it (every
authenticated user can by default); linking to a site needs rights on
the site object, which are not collected. The collector merges ACEs that
differ only in inherited object type, so a class-scoped inherit-only
grant may appear as "all child OUs".
"""

PLUGIN = {
    "plugin_id": 5013,
    "category": "Organizational Units",
    "name": "Non-Tier-0 Principals Can Link GPOs to the Domain or Tier 0 OUs",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-5013",
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
        "MITRE-ATTCK-T1484.001",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.001: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
    ],
    "description": (
        "Flags principals outside Tier 0 granted write access to gPLink or "
        "gPOptions (the 'Manage Group Policy links' delegation) on the domain "
        "root or an OU. They can link any GPO there, or block inheritance of "
        "the baseline GPOs. Critical when the container is the domain root, "
        "an OU above a domain controller, or an OU containing Tier 0 objects; "
        "high otherwise. One finding per trustee."
    ),
    "remediation": (
        "Remove the delegation unless it is intended and scoped to lower-tier "
        "OUs only: `dsacls \"<OU or domain DN>\" /R <trustee>` (removes all of "
        "the trustee's explicit ACEs there; re-grant anything legitimate), or "
        "via the object's Security > Advanced tab, deleting the 'Write gPLink' "
        "/ 'Write gPOptions' entries. Linking GPOs on the domain root, the "
        "Domain Controllers OU and Tier 0 OUs must be limited to Tier 0 "
        "administrators. Afterwards review the container's current gPLink for "
        "GPOs linked by that principal (plugin 9005 lists links)."
    ),
    "base_severity": "critical",
    "query": """
        WITH container AS (
            SELECT d.object_guid, o.dn_current, 'domain root'::text AS label, true AS is_root
            FROM ad_domain d
            JOIN directory_object o ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            UNION ALL
            SELECT u.object_guid, o.dn_current,
                   'OU "' || COALESCE(u.ou_name, o.dn_current) || '"', false
            FROM ad_ou u
            JOIN directory_object o ON o.object_guid = u.object_guid AND o.client_id = u.client_id
                                    AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
        ),
        root_or_ou AS (
            SELECT object_guid FROM container
        ),
        -- Tier 0 principals, minus privilege derived from ACLs on / owning
        -- the domain root or an OU (generic rights or gPLink there are
        -- findings of 5003/5010/9001/9002/this plugin, not exemptions).
        -- DCSync and protected-group membership still count.
        t0p AS (
            SELECT DISTINCT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
              AND NOT (p.privilege_source IN ('tier0_acl_control', 'tier0_acl_control_via_group',
                                              'tier0_ownership', 'tier0_ownership_via_group')
                       AND p.via_object_guid IN (SELECT object_guid FROM root_or_ou))
        ),
        tier0_sid AS (
            SELECT d.object_sid AS sid
            FROM t0p
            JOIN directory_object d
              ON d.object_guid = t0p.object_guid AND d.client_id = %(client_id)s
            WHERE d.object_sid IS NOT NULL
            UNION
            SELECT d.object_sid
            FROM ad_group g
            JOIN directory_object d ON d.object_guid = g.object_guid AND d.client_id = g.client_id
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND g.is_protected_group AND d.object_sid IS NOT NULL
        ),
        tier0_dn AS (
            SELECT lower(d.dn_current) AS dn
            FROM v_tier0_object t
            JOIN directory_object d
              ON d.object_guid = t.object_guid AND d.client_id = t.client_id AND NOT d.is_deleted
            WHERE t.client_id = %(client_id)s
            UNION
            SELECT lower(d.dn_current)
            FROM t0p
            JOIN directory_object d
              ON d.object_guid = t0p.object_guid AND d.client_id = %(client_id)s
             AND NOT d.is_deleted
        ),
        grants AS (
            SELECT a.trustee_sid, c.object_guid AS scope_guid,
                   c.label
                     || CASE WHEN a.inherit_only IS TRUE THEN ' (child OUs)' ELSE '' END AS scope_label,
                   CASE a.object_type_guid
                       WHEN 'f30e3bbe-9ff0-11d1-b603-0000f80367c1' THEN 'Write gPLink'
                       ELSE 'Write gPOptions' END AS right_label,
                   (c.is_root OR EXISTS (
                        SELECT 1 FROM tier0_dn td
                        WHERE right(td.dn, length(c.dn_current) + 1) = ',' || lower(c.dn_current)
                    )) AS reaches_tier0
            FROM acl_edge a
            JOIN container c ON c.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherited = FALSE
              AND (a.access_mask & 32) <> 0
              AND a.object_type_guid IN ('f30e3bbe-9ff0-11d1-b603-0000f80367c1',
                                         'f30e3bbf-9ff0-11d1-b603-0000f80367c1')
              AND (a.inherit_only IS NOT TRUE
                   OR a.inherited_object_type_guid IS NULL
                   OR a.inherited_object_type_guid = 'bf967aa5-0de6-11d0-a285-00aa003049e2')
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', 'S-1-5-10')
              AND a.trustee_sid !~ '^S-1-5-21-[0-9-]+-(512|516|519)$'
              AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = a.trustee_sid)
        ),
        per_scope AS (
            SELECT g.trustee_sid, g.scope_label,
                   string_agg(DISTINCT g.right_label, ', ' ORDER BY g.right_label) AS rights,
                   bool_or(g.reaches_tier0) AS reaches_tier0
            FROM grants g
            GROUP BY g.trustee_sid, g.scope_label
        ),
        per_trustee AS (
            SELECT ps.trustee_sid,
                   bool_or(ps.reaches_tier0) AS reaches_tier0,
                   string_agg(ps.rights || ' on ' || ps.scope_label, '; '
                              ORDER BY ps.scope_label) AS grant_list,
                   jsonb_agg(jsonb_build_object('scope', ps.scope_label, 'rights', ps.rights,
                                                'scope_contains_tier0', ps.reaches_tier0)
                             ORDER BY ps.scope_label) AS grants
            FROM per_scope ps
            GROUP BY ps.trustee_sid
        )
        SELECT
            'fail' AS status,
            tdo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN pt.reaches_tier0 THEN 'critical' ELSE 'high' END AS fd_severity,
            'Principal ' || COALESCE(tdo.sam_account_name, wk.name, pt.trustee_sid)
                || ' can link GPOs: ' || pt.grant_list
                || CASE WHEN pt.reaches_tier0 THEN ' (reaches Tier 0)' ELSE '' END AS summary,
            jsonb_build_object(
                'trustee_sid', pt.trustee_sid,
                'sam_account_name', tdo.sam_account_name,
                'object_class', tdo.object_class,
                'grants', pt.grants
            ) AS detail
        FROM per_trustee pt
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
            ('S-1-5-32-548', 'Account Operators'), ('S-1-5-32-549', 'Server Operators'),
            ('S-1-5-32-550', 'Print Operators'), ('S-1-5-32-551', 'Backup Operators'),
            ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
        ) AS wk(sid, name) ON wk.sid = pt.trustee_sid
    """,
}
