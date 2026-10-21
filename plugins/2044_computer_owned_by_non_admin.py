"""
Plugin 2044: Computer Accounts Owned by a Non-Administrative Account

Reports accounts and groups outside Tier 0 that own computer objects.
When a user joins a computer to the domain, AD makes that user the owner of
the new computer object (and, when the join used MachineAccountQuota,
records them in mS-DS-CreatorSID). An owner can always rewrite the
object's permissions, whatever the DACL says, so the owner can:
  * grant itself the right to read the computer's LAPS password -- the
    local Administrator password LAPS is meant to restrict
    (PingCastle A-LAPS-Joined-Computers);
  * set resource-based constrained delegation on the computer and
    impersonate any user to it -- local admin on that machine.
A computer still owned by the user who joined it, or by the help desk or
provisioning account that did, hands that account control of the machine.

Owners counted as administrative (not reported): Domain Admins, Enterprise
Admins, Schema Admins, the built-in Administrator, Domain Controllers,
SYSTEM, BUILTIN\\Administrators, Enterprise Domain Controllers, any account
or group with adminCount = 1, and effective members of a protected group
(v_privileged_principal source protected_group_member) -- the same rule as
plugin 5007. Domain controllers (plugins 2030 / 4023 cover their owners),
group / delegated managed service accounts and disabled computers are not
counted.

One row per owner (object_guid = the owner), listing up to 50 of its
computers. An owner SID of this domain that matches no collected object is
a deleted account -- nobody can sign in as it -- and is not reported; an
unresolved SID of another domain (a trusted domain's account) is, with
object_guid NULL and the SID in the summary. Severity:
  high   -- it owns a Tier 0 computer (v_tier0_object: an enterprise CA
            host), whose takeover is a path to the domain;
  medium -- it owns a computer it created itself through MachineAccountQuota
            (creator = owner) that LAPS manages: the PingCastle case;
  low    -- otherwise (ownership still gives control of the computer).
Status 'fail' at medium and above. Requires adprofiler 0.9.0 (owners of
every computer, mS-DS-CreatorSID); with older data only DC and protected
computers have an owner and nothing is reported.
"""

PLUGIN = {
    "plugin_id": 2044,
    "category": "Computer Accounts",
    "name": "Computer Accounts Owned by a Non-Administrative Account",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "COMPUTER-2044",
    "framework_tags": [
        "MITRE-ATTCK-T1552",
        "MITRE-ATTCK-T1098",
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3", "ISO-27001-2022-A.8.3", "SOC2-CC6.3",
        "NIST-800-53-IA-5(1)", "CIS-CSC-8-5.4", "ISO-27001-2022-A.5.17", "SOC2-CC6.1",
    ],
    "references": [
        {"title": "PingCastle health check rules (A-LAPS-Joined-Computers)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft: Access control overview (ownership of objects)",
         "url": "https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control"},
        {"title": "Microsoft: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity"},
        {"title": "MITRE ATT&CK T1552: Unsecured Credentials",
         "url": "https://attack.mitre.org/techniques/T1552/"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
    ],
    "description": (
        "Accounts outside Tier 0 own computer objects. An owner can rewrite a computer's "
        "permissions, so it can read the computer's LAPS password and configure delegation "
        "on it -- control of the machine. High when a Tier 0 computer (an enterprise CA host) "
        "is owned; medium when the owner joined a LAPS-managed computer itself through "
        "MachineAccountQuota (PingCastle A-LAPS-Joined-Computers); low otherwise."
    ),
    "remediation": (
        "Make Domain Admins the owner of the listed computers: in Active Directory Users and "
        "Computers, Properties > Security > Advanced > Owner > Change, or "
        "$acl = Get-Acl \"AD:<computer DN>\"; $acl.SetOwner([System.Security.Principal."
        "NTAccount]'<DOMAIN>\\Domain Admins'); Set-Acl \"AD:<computer DN>\" $acl. Then remove "
        "any explicit write-owner, write-permissions or all-extended-rights entries the old "
        "owner has on them. Set MachineAccountQuota to 0 and join computers with a dedicated "
        "account that has the delegated right only, and have the join process reset the owner."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0 AS MATERIALIZED (
            SELECT DISTINCT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
        ),
        computer AS MATERIALIZED (
            SELECT c.object_guid, c.sam_account_name, c.creator_sid, o.owner_sid, o.dn_current, o.object_sid,
                   (c.laps_expiration_legacy IS NOT NULL OR c.laps_expiration_modern IS NOT NULL) AS laps_managed,
                   (t0.object_guid IS NOT NULL) AS is_tier0
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            LEFT JOIN tier0 t0 ON t0.object_guid = c.object_guid
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_enabled
              AND NOT COALESCE(c.is_domain_controller, false)
              AND NOT COALESCE(c.is_gmsa, false) AND NOT COALESCE(c.is_dmsa, false)
              AND o.owner_sid IS NOT NULL
        ),
        admin_owner AS (
            -- Same rule as plugin 5007: well-known Tier 0 SIDs, adminCount = 1,
            -- effective members of a protected group.
            SELECT s.sid
            FROM (SELECT DISTINCT owner_sid AS sid FROM computer) s
            WHERE s.sid LIKE '%%-512' OR s.sid LIKE '%%-518' OR s.sid LIKE '%%-519'
               OR s.sid LIKE '%%-500' OR s.sid LIKE '%%-516'
               OR s.sid IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9')
            UNION
            SELECT p.object_sid
            FROM directory_object p
            JOIN (SELECT u.object_guid FROM ad_user u
                  WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.admin_count = 1
                  UNION
                  SELECT g.object_guid FROM ad_group g
                  WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.admin_count = 1
                  UNION
                  SELECT x.object_guid FROM ad_computer x
                  WHERE x.client_id = %(client_id)s AND x.valid_to IS NULL AND x.admin_count = 1
                  UNION
                  SELECT vp.object_guid FROM v_privileged_principal vp
                  WHERE vp.client_id = %(client_id)s AND vp.privilege_source = 'protected_group_member') a
              ON a.object_guid = p.object_guid
            WHERE p.client_id = %(client_id)s AND NOT p.is_deleted AND p.object_sid IS NOT NULL
        ),
        dom AS (
            SELECT max(o.object_sid) AS domain_sid
            FROM ad_domain d
            JOIN directory_object o ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        owned AS (
            SELECT c.*,
                   (c.creator_sid IS NOT NULL AND c.creator_sid = c.owner_sid) AS owner_is_creator,
                   CASE WHEN c.is_tier0 THEN 3
                        WHEN c.creator_sid = c.owner_sid AND c.laps_managed THEN 2
                        ELSE 1 END AS sev
            FROM computer c
            WHERE NOT EXISTS (SELECT 1 FROM admin_owner a WHERE a.sid = c.owner_sid)
              AND c.owner_sid IS DISTINCT FROM c.object_sid  -- a computer owning itself
        )
        SELECT
            CASE WHEN max(w.sev) >= 2 THEN 'fail' ELSE 'warn' END AS status,
            ow.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(w.sev) WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            CASE WHEN ow.object_class = 'group' THEN 'Group ' ELSE 'Account ' END
                || COALESCE(ow.sam_account_name, w.owner_sid)
                || ' owns ' || count(*) || ' computer object(s)'
                || CASE WHEN bool_or(w.is_tier0)
                        THEN ', including Tier 0 computer(s) '
                             || string_agg(COALESCE(w.sam_account_name, w.dn_current), ', '
                                           ORDER BY lower(COALESCE(w.sam_account_name, w.dn_current)))
                                FILTER (WHERE w.is_tier0)
                        ELSE '' END
                || CASE WHEN count(*) FILTER (WHERE w.owner_is_creator AND w.laps_managed) > 0
                        THEN '; ' || count(*) FILTER (WHERE w.owner_is_creator AND w.laps_managed)
                             || ' of them it joined itself through MachineAccountQuota and LAPS manages, '
                             || 'so it can read their local Administrator password'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'owner_sid', w.owner_sid,
                'owner_name', ow.sam_account_name,
                'owner_object_class', ow.object_class,
                'computer_count', count(*),
                'tier0_computer_count', count(*) FILTER (WHERE w.is_tier0),
                'joined_by_owner_count', count(*) FILTER (WHERE w.owner_is_creator),
                'joined_by_owner_laps_managed_count', count(*) FILTER (WHERE w.owner_is_creator AND w.laps_managed),
                'computers_first_50', to_jsonb((array_agg(jsonb_build_object(
                        'computer', COALESCE(w.sam_account_name, w.dn_current),
                        'tier0', w.is_tier0,
                        'joined_by_owner', w.owner_is_creator,
                        'laps_managed', w.laps_managed)
                    ORDER BY w.sev DESC, lower(COALESCE(w.sam_account_name, w.dn_current))))[1:50]),
                'note', 'Ownership alone gives control; explicit entries the owner may also have on '
                        || 'the computers are not evaluated.'
            ) AS detail
        FROM owned w
        LEFT JOIN directory_object ow
          ON ow.object_sid = w.owner_sid AND ow.client_id = %(client_id)s AND NOT ow.is_deleted
        CROSS JOIN dom
        -- an unresolved SID of this domain is a deleted account
        WHERE ow.object_guid IS NOT NULL OR dom.domain_sid IS NULL
           OR w.owner_sid NOT LIKE dom.domain_sid || '-%%'
        GROUP BY ow.object_guid, ow.sam_account_name, ow.object_class, w.owner_sid
    """,
}
