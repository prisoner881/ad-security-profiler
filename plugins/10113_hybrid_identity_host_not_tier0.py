"""
Plugin 10113: Entra Connect / Cloud Sync / AD FS / PTA Host Not Treated as Tier 0

Generalizes plugin 10010 (which only reports the sync server being a domain
controller). Microsoft's guidance is that every server in the hybrid identity
plane is a Tier 0 asset: the Entra Connect server holds the DCSync-capable
sync credential and can set any synced user's cloud password; an AD FS server
holds the token-signing key (Golden SAML, CISA AA21-008A); a pass-through
authentication agent validates every cloud password and can be backdoored to
accept any password; a Cloud Sync agent holds a gMSA with directory write
rights. Compromise of any one is compromise of the tenant (MITRE ATT&CK
T1556.007 Hybrid Identity, T1606.002 SAML Tokens).

Host identification (AD data, current rows only):
  * Entra Connect Sync: the host named in the MSOL_ / AAD_ sync account's
    installer-generated description ("... running on computer <HOST> ...",
    as plugins 10009/10010 parse it); and the computers allowed to retrieve
    the password of an ADSyncMSA* gMSA (gmsa_password_reader_edge, directly
    or through a group).
  * Entra Cloud Sync agent: computers allowed to retrieve the password of a
    provAgentgMSA* gMSA.
  * AD FS: computers allowed to retrieve the password of a gMSA that holds
    an allow ACE on an AD FS DKM container object (ad_adfs_dkm_object).
    Farms running under a plain user service account cannot be located
    from AD data and are not covered.
  * PTA agents: entra_pta_agent.machine_name (FQDN) matched to a computer's
    dNSHostName or name -- enrichment only; the source is opt-in.
Domain controllers are skipped (plugin 10010 covers them), as are gMSA/dMSA
objects themselves.

A host is reported when any of:
  * it is not Tier 0: not in v_tier0_object and not classified tier 0 in
    object_classification;
  * non-Tier-0 principals can control its computer object: GenericAll,
    GenericWrite, WriteDacl, WriteOwner, All Extended Rights (reads the LAPS
    password), write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD takeover)
    -- through a direct ACE, an ancestor OU / the domain root ACE inherited by
    computer objects (bf967a86-0de6-11d0-a285-00aa003049e2) or control of that
    container; CreateChild of computer objects on an ancestor OU; or
    ownership. Inheritance is cut by a protected OU DACL in between, and
    adminCount=1 computers do not inherit (AdminSDHolder), as in 1037/10111;
  * it is trusted for unconstrained delegation.
GPO-based local administrators (GPP / Restricted Groups) and GPO edit rights
on GPOs linked above the host are not evaluated here. Deny ACEs are not
evaluated. "Non-Tier-0" as in plugin 10111.

Severity: high (fail) when a non-Tier-0 principal can control the host or it is
trusted for unconstrained delegation; medium (warn) when the only problem is
that it is not classified as Tier 0 (classify it in object_classification).
One row per host computer (object_guid = AD objectGUID).
"""

PLUGIN = {
    "plugin_id": 10113,
    "category": "Hybrid Identity",
    "name": "Entra Connect / Cloud Sync / AD FS / PTA Host Not Treated as Tier 0",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10113",
    "framework_tags": [
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-800-53-AC-6(2)",
        "NIST-800-53-AC-3", "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4", "CIS-CSC-8-6.8", "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.8.2", "ISO-27001-2022-A.5.15", "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)", "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1556.007", "MITRE-ATTCK-T1606.002",
        "CISA-AA21-008A",
    ],
    "references": [
        {"title": "Microsoft: Entra Connect -- harden your server (treat as Tier 0)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites"},
        {"title": "Microsoft: Best practices for securing AD FS",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs"},
        {"title": "Microsoft: Pass-through authentication security deep dive",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-security-deep-dive"},
        {"title": "CISA AA21-008A: Detecting post-compromise threat activity in Microsoft cloud environments",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"},
        {"title": "MITRE ATT&CK T1556.007: Modify Authentication Process: Hybrid Identity",
         "url": "https://attack.mitre.org/techniques/T1556/007/"},
    ],
    "description": (
        "Reports Entra Connect Sync, Entra Cloud Sync, AD FS and pass-through authentication "
        "hosts (identified from the sync account description, gMSA password readers, the AD FS "
        "DKM container ACL and the PTA agent list) that are not treated as Tier 0: not "
        "classified Tier 0, controllable by non-Tier-0 principals through their computer "
        "object, its OU or the domain root, or trusted for unconstrained delegation. Any of "
        "these hosts can forge or intercept tenant authentication. Domain controllers are "
        "covered by plugin 10010."
    ),
    "remediation": (
        "Manage each hybrid identity server as Tier 0: move its computer object to a Tier 0 "
        "OU whose ACL and linked GPOs are controlled only by Tier 0 admins, remove non-Tier-0 "
        "delegations (dsacls / Get-Acl \"AD:OU=...\"), set the owner to Domain Admins, clear "
        "unconstrained delegation (Set-ADAccountControl <host>$ -TrustedForDelegation $false), "
        "restrict local administrators and logon rights to Tier 0 accounts, and classify the "
        "host as tier 0 in this tool (object_classification) once done. For AD FS, also "
        "protect the DKM container; for PTA, keep agents on hardened Tier 0 servers and "
        "consider moving to password hash sync."
    ),
    "base_severity": "high",
    "query": """
        WITH sync_desc_host AS (
            SELECT c.object_guid AS host_guid,
                   'Entra Connect Sync (sync account ' || u.sam_account_name || ')' AS role
            FROM ad_user u
            JOIN ad_computer c
              ON c.client_id = u.client_id AND c.valid_to IS NULL
             AND (upper(rtrim(c.sam_account_name, '$'))
                      = upper(substring(u.description from 'running on computer ([^ .,;]+)'))
                  OR upper(split_part(COALESCE(c.dns_hostname, ''), '.', 1))
                      = upper(substring(u.description from 'running on computer ([^ .,;]+)')))
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND u.description IS NOT NULL
              AND substring(u.description from 'running on computer ([^ .,;]+)') IS NOT NULL
              AND (u.sam_account_name LIKE 'MSOL\\_%%'
                   OR u.sam_account_name LIKE 'AAD\\_%%'
                   OR u.description ILIKE '%%Azure AD Connect%%'
                   OR u.description ILIKE '%%Azure Active Directory Connect%%'
                   OR u.description ILIKE '%%Entra Connect%%'
                   OR u.description ILIKE '%%Synchronization Service%%')
        ),
        gmsa_role AS (
            SELECT g.object_guid AS gmsa_guid, g.sam_account_name,
                   CASE WHEN g.sam_account_name ILIKE 'ADSyncMSA%%' THEN 'Entra Connect Sync'
                        ELSE 'Entra Cloud Sync agent' END AS role
            FROM ad_computer g
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_gmsa
              AND (g.sam_account_name ILIKE 'ADSyncMSA%%' OR g.sam_account_name ILIKE 'provAgentgMSA%%')
            UNION
            -- The AD FS service gMSA holds rights on the DKM container.
            SELECT g.object_guid, g.sam_account_name, 'AD FS'
            FROM ad_adfs_dkm_object k
            JOIN acl_edge a
              ON a.client_id = k.client_id AND a.object_guid = k.object_guid
             AND a.valid_to IS NULL AND a.ace_type = 'allow'
            JOIN directory_object d
              ON d.client_id = a.client_id AND d.object_sid = a.trustee_sid AND NOT d.is_deleted
            JOIN ad_computer g
              ON g.client_id = d.client_id AND g.object_guid = d.object_guid
             AND g.valid_to IS NULL AND g.is_gmsa
            WHERE k.client_id = %(client_id)s AND k.valid_to IS NULL
        ),
        gmsa_host AS (
            SELECT hc.object_guid AS host_guid,
                   gr.role || ' (gMSA ' || gr.sam_account_name || ')' AS role
            FROM gmsa_role gr
            JOIN gmsa_password_reader_edge e
              ON e.client_id = %(client_id)s AND e.gmsa_guid = gr.gmsa_guid
             AND e.valid_to IS NULL AND e.ace_type = 'allow'
            JOIN directory_object t
              ON t.client_id = e.client_id AND t.object_sid = e.trustee_sid AND NOT t.is_deleted
            LEFT JOIN v_effective_group_membership vem
              ON vem.client_id = t.client_id AND vem.group_guid = t.object_guid
            JOIN ad_computer hc
              ON hc.client_id = t.client_id AND hc.valid_to IS NULL
             AND hc.object_guid = COALESCE(vem.member_guid, t.object_guid)
        ),
        pta_host AS (
            SELECT c.object_guid AS host_guid, 'Pass-through authentication agent' AS role
            FROM entra_pta_agent p
            JOIN ad_computer c
              ON c.client_id = p.client_id AND c.valid_to IS NULL
             AND (lower(c.dns_hostname) = lower(p.machine_name)
                  OR upper(rtrim(c.sam_account_name, '$')) = upper(split_part(p.machine_name, '.', 1)))
            WHERE p.client_id = %(client_id)s AND p.machine_name IS NOT NULL
        ),
        host_role AS (
            SELECT host_guid, role FROM sync_desc_host
            UNION SELECT host_guid, role FROM gmsa_host
            UNION SELECT host_guid, role FROM pta_host
        ),
        host AS (
            SELECT c.object_guid, c.sam_account_name, c.dns_hostname, c.operating_system,
                   c.admin_count, c.user_account_control, c.unconstrained_delegation,
                   d.object_sid, d.owner_sid, lower(d.dn_current) AS dn_lc, d.dn_current,
                   CASE WHEN c.admin_count = 1
                        THEN d.sd_control IS NOT NULL AND (d.sd_control & 4096) = 0
                        ELSE d.sd_control IS NULL OR (d.sd_control & 4096) = 0
                   END AS inherits,
                   string_agg(DISTINCT hr.role, '; ' ORDER BY hr.role) AS roles,
                   (EXISTS (SELECT 1 FROM v_tier0_object t
                            WHERE t.client_id = c.client_id AND t.object_guid = c.object_guid)
                    OR EXISTS (SELECT 1 FROM object_classification oc
                               WHERE oc.client_id = c.client_id AND oc.object_guid = c.object_guid
                                 AND oc.tier = 0)) AS is_tier0,
                   (c.unconstrained_delegation
                    OR (COALESCE(c.user_account_control, 0) & 524288) <> 0
                    OR EXISTS (SELECT 1 FROM delegation_edge de
                               WHERE de.client_id = c.client_id AND de.source_guid = c.object_guid
                                 AND de.valid_to IS NULL AND de.delegation_type = 'unconstrained'))
                       AS unconstrained
            FROM host_role hr
            JOIN ad_computer c
              ON c.client_id = %(client_id)s AND c.object_guid = hr.host_guid AND c.valid_to IS NULL
            JOIN directory_object d
              ON d.client_id = c.client_id AND d.object_guid = c.object_guid AND NOT d.is_deleted
            WHERE NOT c.is_domain_controller
              AND NOT c.is_gmsa
              AND NOT c.is_dmsa
            GROUP BY c.object_guid, c.client_id, c.sam_account_name, c.dns_hostname, c.operating_system,
                     c.admin_count, c.user_account_control, c.unconstrained_delegation,
                     d.object_sid, d.owner_sid, d.dn_current, d.sd_control
        ),
        tier0_sid AS (
            SELECT DISTINCT d.object_sid::text AS sid
            FROM directory_object d
            WHERE d.client_id = %(client_id)s
              AND d.object_sid IS NOT NULL
              AND NOT d.is_deleted
              AND (EXISTS (SELECT 1 FROM v_privileged_principal p
                           WHERE p.client_id = d.client_id AND p.object_guid = d.object_guid)
                   OR EXISTS (SELECT 1 FROM v_tier0_object t
                              WHERE t.client_id = d.client_id AND t.object_guid = d.object_guid
                                AND t.tier0_reason = 'protected_group'))
        ),
        container AS (
            SELECT o.object_guid, lower(d.dn_current) AS dn_lc,
                   'OU "' || COALESCE(o.ou_name, d.dn_current) || '"' AS label,
                   d.sd_control, TRUE AS is_ou
            FROM ad_ou o
            JOIN directory_object d
              ON d.client_id = o.client_id AND d.object_guid = o.object_guid AND NOT d.is_deleted
            WHERE o.client_id = %(client_id)s AND o.valid_to IS NULL
            UNION ALL
            SELECT dm.object_guid, lower(d.dn_current), 'domain root', d.sd_control, FALSE
            FROM ad_domain dm
            JOIN directory_object d
              ON d.client_id = dm.client_id AND d.object_guid = dm.object_guid AND NOT d.is_deleted
            WHERE dm.client_id = %(client_id)s AND dm.valid_to IS NULL
        ),
        ace AS (
            SELECT a.object_guid, a.trustee_sid::text AS trustee_sid, a.inherit_only,
                   a.inherited_object_type_guid,
                   CASE
                       WHEN (a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0
                           THEN 'GenericAll'
                       WHEN (a.access_mask & 1073741824) <> 0
                         OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                           THEN 'GenericWrite'
                       WHEN (a.access_mask & 262144) <> 0 THEN 'WriteDacl'
                       WHEN (a.access_mask & 524288) <> 0 THEN 'WriteOwner'
                       WHEN (a.access_mask & 256) <> 0 AND a.object_type_guid IS NULL
                           THEN 'AllExtendedRights'
                       WHEN (a.access_mask & 32) <> 0
                        AND a.object_type_guid = '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
                           THEN 'WriteRBCD'
                       WHEN (a.access_mask & 1) <> 0
                        AND (a.object_type_guid IS NULL
                             OR a.object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2')
                           THEN 'CreateChild(computer)'
                   END AS right_name
            FROM acl_edge a
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
        ),
        grant_path AS (
            SELECT h.object_guid, h.object_sid, x.trustee_sid, x.right_name, 'direct ACE' AS path
            FROM host h
            JOIN ace x ON x.object_guid = h.object_guid
            WHERE x.right_name IS NOT NULL AND x.right_name <> 'CreateChild(computer)'
              AND x.inherit_only IS NOT TRUE
            UNION
            SELECT h.object_guid, h.object_sid, x.trustee_sid, x.right_name,
                   CASE WHEN x.right_name = 'CreateChild(computer)' THEN 'on ' ELSE 'inherited from ' END
                       || c.label
            FROM host h
            JOIN container c ON right(h.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc
            JOIN ace x ON x.object_guid = c.object_guid
            WHERE x.right_name IS NOT NULL
              AND (
                    -- Create computer objects in the host's OU (on the OU itself).
                    (x.right_name = 'CreateChild(computer)' AND c.is_ou
                     AND x.inherit_only IS NOT TRUE)
                 OR (x.right_name <> 'CreateChild(computer)' AND h.inherits
                     AND ((x.inherit_only IS NOT TRUE
                           AND x.right_name IN ('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'))
                          OR x.inherited_object_type_guid IS NULL
                          OR x.inherited_object_type_guid = 'bf967a86-0de6-11d0-a285-00aa003049e2')
                     AND NOT EXISTS (
                         SELECT 1 FROM container b
                         WHERE b.is_ou
                           AND b.sd_control IS NOT NULL AND (b.sd_control & 4096) <> 0
                           AND right(h.dn_lc, length(b.dn_lc) + 1) = ',' || b.dn_lc
                           AND right(b.dn_lc, length(c.dn_lc) + 1) = ',' || c.dn_lc))
                  )
            UNION
            SELECT h.object_guid, h.object_sid, h.owner_sid::text, 'Owner', 'object owner'
            FROM host h
            WHERE h.owner_sid IS NOT NULL
        ),
        nontier0 AS (
            SELECT g.object_guid, g.trustee_sid, g.right_name, g.path,
                   COALESCE(tdo.sam_account_name, wk.name, g.trustee_sid) AS trustee_name
            FROM grant_path g
            LEFT JOIN LATERAL (
                SELECT d.sam_account_name FROM directory_object d
                WHERE d.client_id = %(client_id)s AND d.object_sid = g.trustee_sid
                ORDER BY d.is_deleted, d.object_guid LIMIT 1
            ) tdo ON TRUE
            LEFT JOIN (VALUES ('S-1-1-0', 'Everyone'), ('S-1-5-7', 'Anonymous Logon'),
                              ('S-1-5-11', 'Authenticated Users'),
                              ('S-1-5-32-545', 'BUILTIN\\Users'),
                              ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
                      ) AS wk(sid, name) ON wk.sid = g.trustee_sid
            WHERE g.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549',
                                        'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-9', 'S-1-5-10',
                                        'S-1-3-0')
              AND g.trustee_sid !~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(512|516|518|519|526|527)$'
              AND g.trustee_sid IS DISTINCT FROM g.object_sid::text
              AND NOT EXISTS (SELECT 1 FROM tier0_sid s WHERE s.sid = g.trustee_sid)
        ),
        nontier0_agg AS (
            SELECT n.object_guid,
                   string_agg(DISTINCT n.trustee_name, ', ' ORDER BY n.trustee_name) AS trustee_list,
                   jsonb_agg(DISTINCT jsonb_build_object('trustee', n.trustee_name,
                                                         'trustee_sid', n.trustee_sid,
                                                         'right', n.right_name,
                                                         'path', n.path)) AS controllers
            FROM nontier0 n
            GROUP BY n.object_guid
        )
        SELECT
            -- Only "not classified as Tier 0" (no concrete control path) is a
            -- medium warning: these hosts are never in v_tier0_object until the
            -- client classifies them, so it would otherwise be high everywhere.
            CASE WHEN na.object_guid IS NOT NULL OR h.unconstrained THEN 'fail' ELSE 'warn' END AS status,
            h.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN na.object_guid IS NOT NULL OR h.unconstrained THEN 'high' ELSE 'medium' END AS fd_severity,
            'Hybrid identity host "' || COALESCE(rtrim(h.sam_account_name, '$'), h.dns_hostname, h.object_guid::text)
                || '" (' || h.roles || ') is not managed as Tier 0: '
                || array_to_string(array_remove(ARRAY[
                       CASE WHEN NOT h.is_tier0 THEN 'not classified as Tier 0' END,
                       CASE WHEN na.object_guid IS NOT NULL
                            THEN 'non-Tier-0 principal(s) ' || na.trustee_list
                                 || ' can control its computer object' END,
                       CASE WHEN h.unconstrained THEN 'trusted for unconstrained delegation' END
                   ], NULL), '; ') AS summary,
            jsonb_build_object(
                'host_sam_account_name', h.sam_account_name,
                'host_dns_name', h.dns_hostname,
                'host_dn', h.dn_current,
                'operating_system', h.operating_system,
                'roles', h.roles,
                'is_tier0', h.is_tier0,
                'unconstrained_delegation', h.unconstrained,
                'admin_count', h.admin_count,
                'non_tier0_controllers', COALESCE(na.controllers, '[]'::jsonb),
                'note', 'GPO-based local administrators and deny ACEs are not evaluated.',
                'related_plugins', jsonb_build_array(10009, 10010)
            ) AS detail
        FROM host h
        LEFT JOIN nontier0_agg na ON na.object_guid = h.object_guid
        WHERE NOT h.is_tier0 OR na.object_guid IS NOT NULL OR h.unconstrained
    """,
}
