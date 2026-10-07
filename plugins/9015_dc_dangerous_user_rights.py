"""
Plugin 9015: Dangerous User Rights Granted on Domain Controllers

For each domain controller, takes the effective Group Policy user-rights
assignments ([Privilege Rights] in GptTmpl.inf, winning value per right
from v_dc_effective_gpo_setting) and reports principals that hold a
dangerous right beyond the Windows defaults for a DC:

    SeDebugPrivilege, SeTakeOwnershipPrivilege, SeSecurityPrivilege,
    SeEnableDelegationPrivilege, SeManageVolumePrivilege,
    SeRemoteInteractiveLogonRight          Administrators (S-1-5-32-544)
    SeBackupPrivilege, SeRestorePrivilege  Administrators, Backup Operators
                                           (-551), Server Operators (-549)
    SeLoadDriverPrivilege                  Administrators, Print Operators (-550)
    SeInteractiveLogonRight                Administrators, Account / Server /
                                           Print / Backup Operators,
                                           Enterprise Domain Controllers (S-1-5-9)
    SeImpersonatePrivilege                 Administrators, LOCAL SERVICE,
                                           NETWORK SERVICE, SERVICE (S-1-5-6)
    SeAssignPrimaryTokenPrivilege          LOCAL SERVICE, NETWORK SERVICE
    SeTcbPrivilege, SeCreateTokenPrivilege,
    SeSyncAgentPrivilege                   nobody

Always accepted: SYSTEM (S-1-5-18) and Tier 0 principals -- any SID that
resolves to a v_privileged_principal object, plus Domain Admins (-512),
Domain Controllers (-516), Schema Admins (-518), Enterprise Admins (-519),
Administrators and Enterprise Domain Controllers.

Why: on a DC each of these rights is a path to the domain. Debug, Tcb,
CreateToken, AssignPrimaryToken, Impersonate and LoadDriver give SYSTEM
or kernel code execution and LSASS / credential access (MITRE ATT&CK
T1134, T1003); Backup/Restore read or replace ntds.dit and the registry
hives; TakeOwnership and Security (manage auditing and security log)
bypass object ACLs and audit; EnableDelegation lets the holder configure
unconstrained delegation; ManageVolume gives raw disk access; logon
rights on a DC expose Tier 0 credentials on that host. DISA STIG
restricts each of these on domain controllers.

Service identities: Windows adds IIS application-pool identities
(S-1-5-82-*, IIS APPPOOL\<pool>), per-service SIDs (S-1-5-80-*,
NT SERVICE\<service>) and IIS_IUSRS (S-1-5-32-568) to
SeAssignPrimaryTokenPrivilege and SeImpersonatePrivilege when IIS (for
example AD CS Web Enrollment) or such a service is installed on a DC; on
a DC that local change lands in the Default Domain Controllers Policy.
These entries are reported, but on their own they give a WARN at low
severity ("IIS or a service with its own identity runs on a DC") rather
than a FAIL: the exposure is the web server on a Tier 0 host, not a
misgranted right. The same identities in any other right are treated as
ordinary extra principals.

Entries are '*SID' or, when secedit could not resolve it, a plain account
name; names are resolved through well-known names and sAMAccountName.
Per principal the detail gives 'sid' (null when a plain name could not be
mapped to one), 'resolved' (a name was found for it: a directory account,
a well-known principal or a written-out name), and 'principal_class'
(well_known, directory, iis_app_pool, service, unknown_sid -- a SID with
no matching object, e.g. a deleted account -- or unresolved_name).
Severity: critical when Everyone, Authenticated Users, Anonymous Logon,
Users (S-1-5-32-545), Domain Users (-513) or Domain Computers (-515) of
any domain holds one of these rights; high for any other non-default
principal; low (WARN) when only service identities are present. One row
per DC
(object_guid = the DC). Rights not set by any applying GPO keep the DC's
local defaults and are not reported. Batch/service logon rights are out
of scope. Zero rows unless SYSVOL has been collected
(adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9015,
    "category": "Organizational Units",
    "name": "Dangerous User Rights Granted on Domain Controllers",
    "version": "1.1",
    "revision_date": "2026-10-07",
    "control_id": "GPO-9015",
    "framework_tags": [
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3", "CIS-CSC-8-6.8", "ISO-27001-2022-A.5.15", "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3", "HIPAA-164.312(a)(1)",
        "NIST-800-53-AC-6(5)", "ISO-27001-2022-A.8.2",
        "NIST-800-53-CM-6",
        "DISA-STIG",
        "MITRE-ATTCK-T1134", "MITRE-ATTCK-T1003",
    ],
    "references": [
        {"title": "Microsoft Learn: User Rights Assignment",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment"},
        {"title": "MITRE ATT&CK T1134: Access Token Manipulation",
         "url": "https://attack.mitre.org/techniques/T1134/"},
        {"title": "MITRE ATT&CK T1003: OS Credential Dumping",
         "url": "https://attack.mitre.org/techniques/T1003/"},
    ],
    "description": (
        "Reports domain controllers on which Group Policy grants a dangerous user right "
        "(debug programs, act as part of the operating system, create a token, replace a "
        "process token, impersonate, load drivers, back up / restore files, take "
        "ownership, manage auditing and security log, enable delegation, perform volume "
        "maintenance, synchronize directory data, log on locally or through Remote "
        "Desktop) to a principal beyond the Windows defaults for a DC, SYSTEM and Tier 0 "
        "administrators. Each of these rights leads to control of the domain. Critical "
        "when a broad group (Everyone, Authenticated Users, Domain Users, Domain "
        "Computers, Users) holds one, high otherwise. IIS application-pool and service "
        "identities that Windows adds to the token rights when IIS or such a service is "
        "installed on a DC are listed but, on their own, give a low-severity warning that "
        "a web server or service identity runs on a Tier 0 host. One row per DC. Requires "
        "SYSVOL collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Edit the winning GPO named in the finding (normally Default Domain Controllers "
        "Policy): Computer Configuration > Policies > Windows Settings > Security "
        "Settings > Local Policies > User Rights Assignment, and remove the listed "
        "principals from each right so only the defaults remain. Unresolved names "
        "and SIDs with no matching account usually belong to deleted accounts or a typo "
        "-- remove them too. If an application needs a right on a DC, move it off the DC "
        "or grant the right to a dedicated Tier 0 service account (gMSA) only. For IIS "
        "application-pool and service identities (warning only), the fix is to move IIS "
        "-- typically AD CS Web Enrollment or another web role -- off the domain "
        "controller; once the role is removed, remove the leftover entries from the GPO. Run gpupdate /force and verify "
        "with 'secedit /export /cfg c:\\temp\\sec.inf /areas USER_RIGHTS' on each DC."
    ),
    "base_severity": "high",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        dom AS (
            SELECT d.object_sid::text AS dsid
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL AND d.object_sid IS NOT NULL
            ORDER BY d.object_guid
            LIMIT 1
        ),
        wk (sid, name) AS (
            VALUES ('S-1-1-0', 'Everyone'), ('S-1-5-11', 'Authenticated Users'),
                   ('S-1-5-7', 'Anonymous Logon'), ('S-1-5-18', 'SYSTEM'),
                   ('S-1-5-19', 'LOCAL SERVICE'), ('S-1-5-20', 'NETWORK SERVICE'),
                   ('S-1-5-6', 'SERVICE'), ('S-1-5-4', 'INTERACTIVE'), ('S-1-5-2', 'NETWORK'),
                   ('S-1-5-9', 'Enterprise Domain Controllers'),
                   ('S-1-5-32-544', 'Administrators'), ('S-1-5-32-545', 'Users'),
                   ('S-1-5-32-546', 'Guests'), ('S-1-5-32-548', 'Account Operators'),
                   ('S-1-5-32-549', 'Server Operators'), ('S-1-5-32-550', 'Print Operators'),
                   ('S-1-5-32-551', 'Backup Operators'), ('S-1-5-32-555', 'Remote Desktop Users'),
                   ('S-1-5-32-568', 'IIS_IUSRS')
        ),
        name_map AS (
            -- unresolved account names as secedit may write them, by the part
            -- after the last backslash
            SELECT lower(name) AS short_name, sid FROM wk
            UNION ALL
            SELECT v.short_name, dom.dsid || v.rid
            FROM dom CROSS JOIN (VALUES ('domain users', '-513'), ('domain computers', '-515'),
                                        ('domain admins', '-512'), ('enterprise admins', '-519'),
                                        ('schema admins', '-518'), ('domain controllers', '-516'),
                                        ('domain guests', '-514')) AS v(short_name, rid)
            UNION ALL
            SELECT v.short_name, v.sid
            FROM (VALUES ('local system', 'S-1-5-18'), ('nt authority\\system', 'S-1-5-18'))
                 AS v(short_name, sid)
        ),
        rights (right_lower, right_name) AS (
            VALUES ('sedebugprivilege', 'SeDebugPrivilege'),
                   ('sebackupprivilege', 'SeBackupPrivilege'),
                   ('serestoreprivilege', 'SeRestorePrivilege'),
                   ('setakeownershipprivilege', 'SeTakeOwnershipPrivilege'),
                   ('seloaddriverprivilege', 'SeLoadDriverPrivilege'),
                   ('setcbprivilege', 'SeTcbPrivilege'),
                   ('seenabledelegationprivilege', 'SeEnableDelegationPrivilege'),
                   ('sesecurityprivilege', 'SeSecurityPrivilege'),
                   ('seimpersonateprivilege', 'SeImpersonatePrivilege'),
                   ('seassignprimarytokenprivilege', 'SeAssignPrimaryTokenPrivilege'),
                   ('secreatetokenprivilege', 'SeCreateTokenPrivilege'),
                   ('semanagevolumeprivilege', 'SeManageVolumePrivilege'),
                   ('sesyncagentprivilege', 'SeSyncAgentPrivilege'),
                   ('seinteractivelogonright', 'SeInteractiveLogonRight'),
                   ('seremoteinteractivelogonright', 'SeRemoteInteractiveLogonRight')
        ),
        default_allowed (right_lower, sid) AS (
            VALUES ('sedebugprivilege', 'S-1-5-32-544'),
                   ('setakeownershipprivilege', 'S-1-5-32-544'),
                   ('sesecurityprivilege', 'S-1-5-32-544'),
                   ('seenabledelegationprivilege', 'S-1-5-32-544'),
                   ('semanagevolumeprivilege', 'S-1-5-32-544'),
                   ('seremoteinteractivelogonright', 'S-1-5-32-544'),
                   ('sebackupprivilege', 'S-1-5-32-544'), ('sebackupprivilege', 'S-1-5-32-551'),
                   ('sebackupprivilege', 'S-1-5-32-549'),
                   ('serestoreprivilege', 'S-1-5-32-544'), ('serestoreprivilege', 'S-1-5-32-551'),
                   ('serestoreprivilege', 'S-1-5-32-549'),
                   ('seloaddriverprivilege', 'S-1-5-32-544'), ('seloaddriverprivilege', 'S-1-5-32-550'),
                   ('seinteractivelogonright', 'S-1-5-32-544'), ('seinteractivelogonright', 'S-1-5-32-548'),
                   ('seinteractivelogonright', 'S-1-5-32-549'), ('seinteractivelogonright', 'S-1-5-32-550'),
                   ('seinteractivelogonright', 'S-1-5-32-551'), ('seinteractivelogonright', 'S-1-5-9'),
                   ('seimpersonateprivilege', 'S-1-5-32-544'), ('seimpersonateprivilege', 'S-1-5-19'),
                   ('seimpersonateprivilege', 'S-1-5-20'), ('seimpersonateprivilege', 'S-1-5-6'),
                   ('seassignprimarytokenprivilege', 'S-1-5-19'),
                   ('seassignprimarytokenprivilege', 'S-1-5-20')
        ),
        tier0_sid AS (
            SELECT DISTINCT d.object_sid::text AS sid
            FROM v_privileged_principal p
            JOIN directory_object d
              ON d.object_guid = p.object_guid AND d.client_id = p.client_id AND NOT d.is_deleted
            WHERE p.client_id = %(client_id)s AND d.object_sid IS NOT NULL
            UNION
            SELECT v.sid FROM (VALUES ('S-1-5-18'), ('S-1-5-32-544'), ('S-1-5-9')) AS v(sid)
            UNION
            SELECT dom.dsid || r.rid
            FROM dom CROSS JOIN (VALUES ('-512'), ('-516'), ('-518'), ('-519')) AS r(rid)
        ),
        eff AS (
            SELECT e.dc_guid, r.right_lower, r.right_name, e.setting_value, e.winning_gpo_guid
            FROM v_dc_effective_gpo_setting e
            JOIN rights r ON r.right_lower = lower(e.setting_key)
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND e.client_id = %(client_id)s
              AND e.source = 'security_template'
              AND lower(e.section) = 'privilege rights'
        ),
        entry AS (
            SELECT DISTINCT e.dc_guid, e.right_lower, e.right_name, e.winning_gpo_guid,
                   btrim(x) AS raw_entry
            FROM eff e
            CROSS JOIN LATERAL unnest(string_to_array(COALESCE(e.setting_value, ''), ',')) AS x
            WHERE btrim(x) <> ''
        ),
        resolved AS (
            SELECT en.*,
                   CASE WHEN left(en.raw_entry, 1) = '*'
                        THEN upper(substr(en.raw_entry, 2))
                        ELSE COALESCE(
                            (SELECT nm.sid FROM name_map nm
                              WHERE nm.short_name = lower(en.raw_entry)
                                 OR nm.short_name = lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1)))
                              ORDER BY nm.sid LIMIT 1),
                            (SELECT o.object_sid::text FROM directory_object o
                              WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
                                AND o.object_sid IS NOT NULL
                                AND lower(o.sam_account_name)
                                    = lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1)))
                              ORDER BY o.object_guid LIMIT 1))
                   END AS sid
            FROM entry en
        ),
        extra AS (
            SELECT r.*,
                   COALESCE(
                       (SELECT o.sam_account_name FROM directory_object o
                         WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
                           AND o.object_sid::text = r.sid AND o.sam_account_name IS NOT NULL
                         ORDER BY o.object_guid LIMIT 1),
                       (SELECT wk.name FROM wk WHERE wk.sid = r.sid),
                       CASE WHEN left(r.raw_entry, 1) <> '*' THEN r.raw_entry
                            WHEN r.sid ~ '^S-1-5-82-' THEN 'IIS application pool ' || r.sid
                            WHEN r.sid ~ '^S-1-5-80-' THEN 'service ' || r.sid
                            ELSE r.sid END
                   ) AS display_name,
                   (r.sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545')
                    OR r.sid ~ '^S-1-5-21-[0-9-]+-(513|515)$') AS broad,
                   CASE WHEN r.sid ~ '^S-1-5-82-' OR split_part(lower(r.raw_entry), chr(92), 1) = 'iis apppool'
                        THEN 'iis_app_pool'
                        WHEN r.sid ~ '^S-1-5-80-' OR split_part(lower(r.raw_entry), chr(92), 1) = 'nt service'
                        THEN 'service'
                        WHEN EXISTS (SELECT 1 FROM wk WHERE wk.sid = r.sid) THEN 'well_known'
                        WHEN EXISTS (SELECT 1 FROM directory_object o
                                      WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
                                        AND o.object_sid::text = r.sid)
                        THEN 'directory'
                        WHEN r.sid IS NOT NULL THEN 'unknown_sid'
                        ELSE 'unresolved_name'
                   END AS principal_class,
                   COALESCE(r.right_lower IN ('seassignprimarytokenprivilege', 'seimpersonateprivilege')
                            AND (r.sid ~ '^S-1-5-8[02]-' OR r.sid = 'S-1-5-32-568'
                                 OR split_part(lower(r.raw_entry), chr(92), 1)
                                    IN ('iis apppool', 'nt service')), false) AS service_only
            FROM resolved r
            WHERE r.sid IS NULL
               OR (NOT EXISTS (SELECT 1 FROM default_allowed da
                               WHERE da.right_lower = r.right_lower AND da.sid = r.sid)
                   AND NOT EXISTS (SELECT 1 FROM tier0_sid t WHERE t.sid = r.sid))
        ),
        per_right AS (
            SELECT x.dc_guid, x.right_name, x.winning_gpo_guid,
                   bool_or(COALESCE(x.broad, false)) AS broad,
                   bool_or(NOT x.service_only) AS dangerous,
                   string_agg(x.display_name, ', ' ORDER BY lower(x.display_name), x.raw_entry) AS principals,
                   jsonb_agg(jsonb_build_object(
                       'entry', x.raw_entry, 'sid', x.sid, 'name', x.display_name,
                       'resolved', x.principal_class IN ('well_known', 'directory')
                                   OR (x.principal_class IN ('iis_app_pool', 'service')
                                       AND left(x.raw_entry, 1) <> '*'),
                       'principal_class', x.principal_class,
                       'service_identity', x.service_only,
                       'broad_principal', COALESCE(x.broad, false))
                       ORDER BY lower(x.display_name), x.raw_entry) AS principal_list
            FROM extra x
            GROUP BY x.dc_guid, x.right_name, x.winning_gpo_guid
        ),
        per_dc AS (
            SELECT pr.dc_guid,
                   bool_or(pr.broad) AS broad,
                   bool_or(pr.dangerous) AS dangerous,
                   string_agg(pr.right_name || ': ' || pr.principals, '; ' ORDER BY pr.right_name) AS rights_text,
                   jsonb_agg(jsonb_build_object(
                       'right', pr.right_name,
                       'extra_principals', pr.principal_list,
                       'winning_gpo_object_guid', pr.winning_gpo_guid,
                       'winning_gpo_guid', g.gpo_guid,
                       'winning_gpo_display_name', g.display_name)
                       ORDER BY pr.right_name) AS rights
            FROM per_right pr
            LEFT JOIN ad_gpo g
              ON g.object_guid = pr.winning_gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            GROUP BY pr.dc_guid
        )
        SELECT
            CASE WHEN p.dangerous THEN 'fail' ELSE 'warn' END AS status,
            p.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.broad THEN 'critical' WHEN p.dangerous THEN 'high' ELSE 'low' END AS fd_severity,
            'Domain controller ' || COALESCE(c.dns_hostname, d.sam_account_name, d.dn_current)
                || CASE WHEN p.dangerous
                        THEN ' is granted dangerous user rights beyond the defaults by Group Policy'
                             || CASE WHEN p.broad THEN ' (including a broad group)' ELSE '' END
                        ELSE ' grants token rights to IIS application-pool or service identities '
                             || 'by Group Policy (IIS or a service with its own identity is '
                             || 'installed on the domain controller)'
                   END
                || ': ' || p.rights_text AS summary,
            jsonb_build_object(
                'dc_dn', d.dn_current,
                'dc_dns_hostname', c.dns_hostname,
                'broad_principal_present', p.broad,
                'service_identities_only', NOT p.dangerous,
                'rights', p.rights,
                'note', 'effective [Privilege Rights] value of the winning GPO; SYSTEM, Tier 0 principals and Windows DC defaults are not listed'
            ) AS detail
        FROM per_dc p
        JOIN directory_object d
          ON d.object_guid = p.dc_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        LEFT JOIN ad_computer c
          ON c.object_guid = p.dc_guid AND c.client_id = %(client_id)s AND c.valid_to IS NULL
    """,
}
