"""
Plugin 5011: AdminSDHolder DACL Inheritance Not Disabled / Protected Objects Inheriting Permissions

Detects two related breakdowns of the AdminSDHolder / SDProp protection
model, using the security descriptor control flags the collector stores
since schema v38 (directory_object.sd_control; 0x1000 =
SE_DACL_PROTECTED, i.e. "inheritance disabled"):

  (a) The AdminSDHolder object itself (CN=AdminSDHolder,CN=System,...)
      does not have SE_DACL_PROTECTED set. AdminSDHolder's DACL is the
      template SDProp copies onto every protected account and group every
      60 minutes. With inheritance enabled, any inheritable ACE on the
      domain root or CN=System (including one added by an attacker, or a
      broad delegation such as Exchange's) flows into the template and,
      from there, onto Domain Admins, Enterprise Admins, krbtgt and every
      other protected object -- a classic persistence technique. Microsoft
      ships AdminSDHolder with inheritance disabled. -> high.

  (b) A current Tier 0 principal (v_privileged_principal, or a
      well-known protected account/group such as Administrator, krbtgt,
      Domain Admins, Account Operators) that carries adminCount = 1 but
      whose DACL is NOT protected. SDProp sets SE_DACL_PROTECTED on every
      object it protects; adminCount = 1 with inheritance enabled means
      SDProp has not processed the object since inheritance was turned
      back on -- SDProp is not running (PDC emulator problem), the object
      is excluded through dSHeuristics dwAdminSDExMask (Account/Server/
      Print/Backup Operators can be excluded), or someone re-enabled
      inheritance minutes ago. Either way the object currently inherits
      ACEs from its OU and the domain root, so OU delegations reach a
      Tier 0 account. -> medium, one row per object.

Why it matters: Microsoft "Appendix C: Protected Accounts and Groups in
Active Directory"; Purple Knight / PingCastle AdminSDHolder checks;
MITRE ATT&CK T1098 (AdminSDHolder persistence).

Data caveats: sd_control is NULL for objects whose security descriptor
the collector does not read and for rows collected before schema v38;
such objects are skipped (not reported as compliant or non-compliant).
The collector reads the SD of AdminSDHolder, the domain root, OUs, DCs
and adminCount = 1 objects, which covers both checks.
dsheuristics_admin_sd_ex_mask (ad_domain) is shown in the detail so an
intentional dwAdminSDExMask exclusion can be recognised; it does not
suppress the finding (an excluded operator group is still Tier 0 here).
Stale adminCount = 1 on accounts that are no longer privileged is not
evaluated: only current Tier 0 principals are.
"""

PLUGIN = {
    "plugin_id": 5011,
    "category": "ACLs",
    "name": "AdminSDHolder DACL Inheritance Not Disabled / Protected Objects Inheriting Permissions",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "ACL-5011",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: Appendix C - Protected Accounts and Groups in Active Directory",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
    ],
    "description": (
        "Flags the AdminSDHolder object when its DACL inheritance is not "
        "disabled (SE_DACL_PROTECTED missing), so inheritable ACEs from the "
        "domain root or CN=System flow into the template SDProp stamps on "
        "every protected account (high), and current Tier 0 principals with "
        "adminCount = 1 whose DACL still inherits permissions -- SDProp "
        "should have disabled inheritance on them, which indicates SDProp "
        "is not running or the object is excluded via dwAdminSDExMask "
        "(medium). Objects whose security descriptor flags were not "
        "collected are skipped."
    ),
    "remediation": (
        "AdminSDHolder: in ADSI Edit open CN=AdminSDHolder,CN=System,<domain> "
        "> Properties > Security > Advanced and choose 'Disable inheritance' "
        "(convert inherited permissions to explicit, then remove any that "
        "are not in the Microsoft default), or with PowerShell: "
        "`$p='AD:CN=AdminSDHolder,CN=System,DC=corp,DC=local'; $a=Get-Acl $p; "
        "$a.SetAccessRuleProtection($true,$true); Set-Acl $p $a`. Review "
        "the AdminSDHolder ACL for added trustees (plugin 5002). Protected "
        "objects: confirm SDProp runs on the PDC emulator (Directory Service "
        "event log; force a run via the RunProtectAdminGroupsTask rootDSE "
        "operation), check dSHeuristics dwAdminSDExMask, and if the account "
        "is no longer meant to be privileged clear adminCount and re-enable "
        "inheritance deliberately instead."
    ),
    "base_severity": "high",
    "query": """
        WITH dom AS (
            SELECT d.dsheuristics_admin_sd_ex_mask
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            ORDER BY d.object_guid
            LIMIT 1
        ),
        -- Current Tier 0 principals: the shared definition, plus the
        -- well-known protected accounts and groups by SID/RID.
        tier0 AS (
            SELECT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
            UNION
            SELECT o.object_guid
            FROM directory_object o
            WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
              AND (o.object_sid ~ '^S-1-5-21-[0-9-]+-(500|502|512|516|518|519|521|526|527)$'
                   OR o.object_sid IN ('S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549',
                                       'S-1-5-32-550', 'S-1-5-32-551', 'S-1-5-32-552'))
        ),
        protected_obj AS (
            SELECT u.object_guid, u.admin_count, 'user'::text AS kind
            FROM ad_user u WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
            UNION ALL
            SELECT c.object_guid, c.admin_count, 'computer'
            FROM ad_computer c WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
            UNION ALL
            SELECT g.object_guid, g.admin_count, 'group'
            FROM ad_group g WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
        )
        -- (a) AdminSDHolder itself
        SELECT
            'fail' AS status,
            o.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'AdminSDHolder (' || o.dn_current || ') does not have DACL inheritance '
                || 'disabled: inheritable ACEs from the domain root and CN=System flow '
                || 'into the template SDProp applies to every protected account and group'
                AS summary,
            jsonb_build_object(
                'dn', o.dn_current,
                'sd_control', o.sd_control,
                'se_dacl_protected', false
            ) AS detail
        FROM directory_object o
        WHERE o.client_id = %(client_id)s
          AND NOT o.is_deleted
          AND lower(o.dn_current) LIKE 'cn=adminsdholder,cn=system,%%'
          AND o.sd_control IS NOT NULL
          AND (o.sd_control & 4096) = 0

        UNION ALL

        -- (b) Tier 0 principals with adminCount = 1 whose DACL inherits
        SELECT
            'fail',
            o.object_guid,
            NULL, NULL, NULL, NULL,
            'medium',
            'Tier 0 ' || po.kind || ' ' || COALESCE(o.sam_account_name, o.object_sid, o.dn_current)
                || ' has adminCount = 1 but its DACL inherits permissions (SE_DACL_PROTECTED '
                || 'not set): SDProp is not protecting it (SDProp not running, or excluded '
                || 'via dSHeuristics dwAdminSDExMask)',
            jsonb_build_object(
                'dn', o.dn_current,
                'object_sid', o.object_sid,
                'sam_account_name', o.sam_account_name,
                'object_kind', po.kind,
                'admin_count', po.admin_count,
                'sd_control', o.sd_control,
                'dsheuristics_admin_sd_ex_mask', (SELECT dom.dsheuristics_admin_sd_ex_mask FROM dom)
            )
        FROM protected_obj po
        JOIN directory_object o
          ON o.object_guid = po.object_guid AND o.client_id = %(client_id)s
         AND NOT o.is_deleted
        WHERE po.admin_count = 1
          AND o.sd_control IS NOT NULL
          AND (o.sd_control & 4096) = 0
          AND EXISTS (SELECT 1 FROM tier0 t WHERE t.object_guid = po.object_guid)
    """,
}
