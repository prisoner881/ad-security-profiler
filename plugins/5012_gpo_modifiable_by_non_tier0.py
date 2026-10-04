"""
Plugin 5012: Non-Tier-0 Principals Can Modify Group Policy Objects

Detects Group Policy Objects (groupPolicyContainer objects, ad_gpo) whose
security descriptor lets a principal outside Tier 0 change them: allow
ACEs that apply to the GPO itself (not inherit-only) granting
GenericAll, GenericWrite (WRITE_PROP with no object type, as AD stores
it), WriteDacl, WriteOwner, or WRITE_PROP on gPCFileSysPath
(f30e3bc1-9ff0-11d1-b603-0000f80367c1, which redirects clients to an
attacker-controlled policy folder) -- plus a non-Tier-0 owner of the
GPO object (an owner can always rewrite the DACL). GPMC's "Edit
settings" delegation is WRITE_PROP on every property, so it is caught
as GenericWrite.

Why it matters: whoever can edit a GPO runs code (scheduled tasks,
startup scripts, user rights, restricted groups) on every computer and
user the GPO applies to. A GPO linked to the domain root, the Domain
Controllers OU, a site, or an OU holding Tier 0 objects makes that edit
domain compromise. BloodHound GenericWrite/WriteDacl-on-GPO edges,
PingCastle P-DelegationGPO, ANSSI, CISA/Five Eyes 2024 AD guidance;
MITRE ATT&CK T1484.001 (Group Policy Modification).

Severity, per GPO, from where it applies (enabled links in
gpo_link_edge only):
  critical -- linked to the domain root, an OU containing a domain
              controller (v_tier0_object 'domain_controller_ou', i.e.
              every OU above a DC), any site, or an OU that contains a
              Tier 0 object (v_tier0_object) or Tier 0 principal
              (v_privileged_principal) anywhere below it;
  high     -- linked only elsewhere;
  low      -- not linked (or every link disabled): editing it has no
              effect until someone links it.
One row per GPO, listing every non-Tier-0 trustee and its rights.

Excluded trustees (expected holders / Tier 0): SYSTEM, Administrators,
Domain Admins, Enterprise Admins, Domain Controllers, Enterprise Domain
Controllers (read-only by default anyway), Creator Owner (an inherit-only
placeholder), every principal in v_privileged_principal and every
AdminSDHolder-protected group (its members are Tier 0). Trustee SIDs
that resolve to no collected object (Everyone, Authenticated Users,
foreign or orphaned SIDs) are reported by SID/well-known name.

Caveats: the SYSVOL folder (\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{GUID})
holds the actual policy files and has its own NTFS permissions, which
are not collected (they normally mirror the GPO's DACL, and GPMC keeps
them in sync). Editing policy content needs write access to both; a
write to gPCFileSysPath alone is enough to redirect the GPO to a share
the attacker controls. Block inheritance below a linked container is not
considered. GPO ACLs and owners are collected from schema v38 on; before
that this plugin returns nothing.
"""

PLUGIN = {
    "plugin_id": 5012,
    "category": "Organizational Units",
    "name": "Non-Tier-0 Principals Can Modify Group Policy Objects",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-5012",
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
        "DISA-STIG",
        "MITRE-ATTCK-T1484.001",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification - Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
        {"title": "BloodHound (SpecterOps): GenericWrite edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-write"},
    ],
    "description": (
        "Flags each GPO on which a principal outside Tier 0 holds GenericAll, "
        "GenericWrite (incl. GPMC 'Edit settings'), WriteDacl, WriteOwner or "
        "write access to gPCFileSysPath, or owns the GPO object. Critical when "
        "the GPO is linked (enabled link) to the domain root, an OU above a "
        "domain controller, a site, or an OU containing Tier 0 objects; high "
        "when linked elsewhere; low when not linked. SYSVOL folder permissions "
        "are not collected; they normally mirror the GPO's DACL."
    ),
    "remediation": (
        "In GPMC, select the GPO > Delegation > Advanced and remove the "
        "principal's Edit/Full Control/Modify permissions/Modify owner rights "
        "(or `Set-GPPermission -Name '<GPO>' -TargetName '<trustee>' "
        "-TargetType Group -PermissionLevel None -Replace`). Take ownership "
        "back for Domain Admins if the owner is not Tier 0. GPOs that apply "
        "to domain controllers or Tier 0 OUs must be editable only by Tier 0 "
        "administrators; delegate editing of lower-tier GPOs only on GPOs "
        "linked exclusively to lower-tier OUs. Then verify the SYSVOL folder "
        "permissions match (GPMC > Status / gpotool) and review the GPO's "
        "settings and gPCFileSysPath for tampering."
    ),
    "base_severity": "critical",
    "query": """
        WITH tier0_sid AS (
            SELECT d.object_sid AS sid
            FROM v_privileged_principal p
            JOIN directory_object d
              ON d.object_guid = p.object_guid AND d.client_id = p.client_id
            WHERE p.client_id = %(client_id)s AND d.object_sid IS NOT NULL
            UNION
            SELECT d.object_sid
            FROM ad_group g
            JOIN directory_object d
              ON d.object_guid = g.object_guid AND d.client_id = g.client_id
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND g.is_protected_group AND d.object_sid IS NOT NULL
        ),
        gpo AS (
            SELECT g.object_guid, g.display_name, g.gpo_guid, g.gpo_flags,
                   o.dn_current, o.owner_sid
            FROM ad_gpo g
            JOIN directory_object o
              ON o.object_guid = g.object_guid AND o.client_id = g.client_id
             AND NOT o.is_deleted
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
        ),
        grants AS (
            SELECT a.object_guid AS gpo_guid, a.trustee_sid,
                   bool_or((a.access_mask & 983551) = 983551
                           OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   bool_or(((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                           OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) <> 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) <> 0) AS is_write_owner,
                   bool_or((a.access_mask & 32) <> 0
                           AND a.object_type_guid = 'f30e3bc1-9ff0-11d1-b603-0000f80367c1')
                       AS is_write_path,
                   false AS is_owner
            FROM acl_edge a
            JOIN gpo ON gpo.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) <> 0
                    OR (a.access_mask & 983551) = 983551
                    OR ((a.access_mask & 32) <> 0
                        AND (a.object_type_guid IS NULL
                             OR a.object_type_guid = 'f30e3bc1-9ff0-11d1-b603-0000f80367c1'))
                  )
            GROUP BY a.object_guid, a.trustee_sid
            UNION ALL
            SELECT gpo.object_guid, gpo.owner_sid, false, false, false, false, false, true
            FROM gpo
            WHERE gpo.owner_sid IS NOT NULL
        ),
        per_trustee AS (
            SELECT gr.gpo_guid, gr.trustee_sid,
                   bool_or(gr.is_generic_all) AS ga, bool_or(gr.is_generic_write) AS gw,
                   bool_or(gr.is_write_dacl) AS wd, bool_or(gr.is_write_owner) AS wo,
                   bool_or(gr.is_write_path) AS wp, bool_or(gr.is_owner) AS own
            FROM grants gr
            WHERE gr.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0')
              AND gr.trustee_sid !~ '^S-1-5-21-[0-9-]+-(512|516|519)$'
              AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = gr.trustee_sid)
            GROUP BY gr.gpo_guid, gr.trustee_sid
        ),
        labelled AS (
            SELECT pt.gpo_guid, pt.trustee_sid,
                   COALESCE(tdo.sam_account_name, wk.name, pt.trustee_sid) AS trustee_label,
                   tdo.object_class AS trustee_object_class,
                   (SELECT string_agg(x, ', ' ORDER BY n) FROM (VALUES
                        (1, CASE WHEN pt.ga THEN 'GenericAll' END),
                        (2, CASE WHEN pt.gw AND NOT pt.ga THEN 'GenericWrite' END),
                        (3, CASE WHEN pt.wd AND NOT pt.ga THEN 'WriteDacl' END),
                        (4, CASE WHEN pt.wo AND NOT pt.ga THEN 'WriteOwner' END),
                        (5, CASE WHEN pt.wp AND NOT pt.ga AND NOT pt.gw THEN 'Write gPCFileSysPath' END),
                        (6, CASE WHEN pt.own THEN 'Owner' END)
                    ) AS v(n, x) WHERE x IS NOT NULL) AS rights
            FROM per_trustee pt
            LEFT JOIN LATERAL (
                SELECT d.sam_account_name, d.object_class
                FROM directory_object d
                WHERE d.client_id = %(client_id)s AND d.object_sid = pt.trustee_sid
                ORDER BY d.is_deleted, d.object_guid
                LIMIT 1
            ) tdo ON TRUE
            LEFT JOIN (VALUES
                ('S-1-1-0', 'Everyone'), ('S-1-5-7', 'Anonymous Logon'),
                ('S-1-5-11', 'Authenticated Users'), ('S-1-5-10', 'Self'),
                ('S-1-5-32-545', 'Users'), ('S-1-5-32-548', 'Account Operators'),
                ('S-1-5-32-549', 'Server Operators'), ('S-1-5-32-550', 'Print Operators'),
                ('S-1-5-32-551', 'Backup Operators')
            ) AS wk(sid, name) ON wk.sid = pt.trustee_sid
        ),
        per_gpo AS (
            SELECT l.gpo_guid,
                   string_agg(l.trustee_label || ' (' || l.rights || ')', '; '
                              ORDER BY l.trustee_label, l.trustee_sid) AS trustee_list,
                   jsonb_agg(jsonb_build_object(
                       'trustee_sid', l.trustee_sid,
                       'trustee', l.trustee_label,
                       'trustee_object_class', l.trustee_object_class,
                       'rights', l.rights
                   ) ORDER BY l.trustee_label, l.trustee_sid) AS trustees
            FROM labelled l
            GROUP BY l.gpo_guid
        ),
        -- Tier 0 things, by DN, to decide whether an OU "contains Tier 0"
        tier0_dn AS (
            SELECT lower(d.dn_current) AS dn
            FROM v_tier0_object t
            JOIN directory_object d
              ON d.object_guid = t.object_guid AND d.client_id = t.client_id AND NOT d.is_deleted
            WHERE t.client_id = %(client_id)s
            UNION
            SELECT lower(d.dn_current)
            FROM v_privileged_principal p
            JOIN directory_object d
              ON d.object_guid = p.object_guid AND d.client_id = p.client_id AND NOT d.is_deleted
            WHERE p.client_id = %(client_id)s
        ),
        links AS (
            SELECT l.gpo_guid, l.container_guid,
                   COALESCE(cd.dn_current, l.container_guid::text) AS container_dn,
                   CASE
                       WHEN dm.object_guid IS NOT NULL THEN 'domain root'
                       WHEN st.object_guid IS NOT NULL THEN 'site'
                       WHEN EXISTS (SELECT 1 FROM v_tier0_object t
                                    WHERE t.client_id = %(client_id)s
                                      AND t.object_guid = l.container_guid
                                      AND t.tier0_reason = 'domain_controller_ou')
                           THEN 'domain controller OU'
                       WHEN ou.object_guid IS NOT NULL AND EXISTS (
                                SELECT 1 FROM tier0_dn td
                                WHERE right(td.dn, length(cd.dn_current) + 1) = ',' || lower(cd.dn_current))
                           THEN 'OU containing Tier 0 objects'
                       ELSE 'other'
                   END AS link_kind
            FROM gpo_link_edge l
            LEFT JOIN directory_object cd
              ON cd.object_guid = l.container_guid AND cd.client_id = l.client_id
            LEFT JOIN ad_domain dm
              ON dm.object_guid = l.container_guid AND dm.client_id = l.client_id AND dm.valid_to IS NULL
            LEFT JOIN ad_site st
              ON st.object_guid = l.container_guid AND st.client_id = l.client_id AND st.valid_to IS NULL
            LEFT JOIN ad_ou ou
              ON ou.object_guid = l.container_guid AND ou.client_id = l.client_id AND ou.valid_to IS NULL
            WHERE l.client_id = %(client_id)s
              AND l.valid_to IS NULL
              AND l.link_enabled
        ),
        per_gpo_links AS (
            SELECT lk.gpo_guid,
                   bool_or(lk.link_kind <> 'other') AS tier0_link,
                   string_agg(DISTINCT lk.link_kind, ', ' ORDER BY lk.link_kind)
                       FILTER (WHERE lk.link_kind <> 'other') AS tier0_kinds,
                   jsonb_agg(jsonb_build_object('container_dn', lk.container_dn,
                                                'link_kind', lk.link_kind)
                             ORDER BY lk.container_dn) AS link_list
            FROM links lk
            GROUP BY lk.gpo_guid
        )
        SELECT
            CASE WHEN pl.gpo_guid IS NULL THEN 'warn' ELSE 'fail' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN pl.tier0_link THEN 'critical'
                 WHEN pl.gpo_guid IS NOT NULL THEN 'high'
                 ELSE 'low' END AS fd_severity,
            'GPO "' || COALESCE(g.display_name, g.gpo_guid::text, g.object_guid::text)
                || '" can be modified by non-Tier-0 principal(s): ' || pg.trustee_list
                || CASE WHEN pl.tier0_link THEN ' -- it applies to Tier 0 (linked to: '
                                                || pl.tier0_kinds || ')'
                        WHEN pl.gpo_guid IS NOT NULL THEN ' -- linked to non-Tier-0 containers only'
                        ELSE ' -- not linked (no enabled link)' END AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'dn', g.dn_current,
                'gpo_flags', g.gpo_flags,
                'owner_sid', g.owner_sid,
                'trustees', pg.trustees,
                'enabled_links', COALESCE(pl.link_list, '[]'::jsonb)
            ) AS detail
        FROM per_gpo pg
        JOIN gpo g ON g.object_guid = pg.gpo_guid
        LEFT JOIN per_gpo_links pl ON pl.gpo_guid = pg.gpo_guid
    """,
}
