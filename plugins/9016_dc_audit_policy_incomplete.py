r"""
Plugin 9016: Domain Controller Audit Policy Incomplete

Detects domain controllers whose effective Group Policy does not audit the
security events needed to detect and investigate attacks on Active
Directory (logons, Kerberos ticket requests, account and group changes,
directory changes, policy changes, privilege use, process creation).

Required advanced audit subcategories (required bits: 1 success, 2 failure,
3 both), following Microsoft's audit policy recommendations for domain
controllers:
    Credential Validation 3, Kerberos Authentication Service 3,
    Kerberos Service Ticket Operations 3, Computer Account Management 1,
    Security Group Management 1, User Account Management 3,
    Other Account Management Events 1, Directory Service Access 2,
    Directory Service Changes 1, Audit Policy Change 1,
    Authentication Policy Change 1, Sensitive Privilege Use 3, Logon 3,
    Special Logon 1, Process Creation 1.
A subcategory is satisfied when (configured value & required) = required.

Which policy is evaluated:
  * If any advanced audit subcategory (audit.csv; gpo_setting_edge source
    'audit') is in effect on the DC, only the advanced policy is evaluated:
    Windows applies subcategory settings over the legacy categories by
    default ("Audit: Force audit policy subcategory settings to override
    audit policy category settings"). Subcategories are matched by GUID,
    falling back to the English subcategory name (leading 'Audit ' removed).
  * Otherwise the legacy [Event Audit] categories of GptTmpl.inf are mapped:
    AuditAccountLogon -> Credential Validation and both Kerberos
    subcategories; AuditAccountManage -> the four account-management
    subcategories; AuditDSAccess -> the two directory-service ones;
    AuditPolicyChange -> the two policy-change ones; AuditPrivilegeUse ->
    Sensitive Privilege Use; AuditLogonEvents -> Logon and Special Logon;
    AuditProcessTracking -> Process Creation.

Results (one row per DC):
  * Some required subcategories missing or insufficient -> fail, medium,
    listing what is not audited and what is incomplete. If only missing
    (not explicitly insufficient) subcategories are reported and a GPO
    applying to the DC could not be read from SYSVOL, the result is
    downgraded to warn and the unreadable GPOs are listed.
  * Neither advanced nor legacy audit policy configured by any applying GPO
    -> warn, medium (audit policy is not enforced by Group Policy; the DC
    may have a local policy).
Why it matters: without these events, Kerberoasting, DCSync, privileged
group changes, password spraying and malicious process execution on DCs go
undetected and cannot be investigated afterwards (MITRE ATT&CK T1562.002).

Data: winning machine-scope values per DC (v_dc_effective_gpo_setting).
Advanced audit policy from several GPOs merges per subcategory, which the
view reflects. Site-linked GPOs, WMI filters and local policy are not
visible. Gating: returns nothing unless SYSVOL has been collected for the
client (ad_gpo_sysvol has an 'ok' row). Read-only DCs are included.
"""

PLUGIN = {
    "plugin_id": 9016,
    "category": "Organizational Units",
    "name": "Domain Controller Audit Policy Incomplete",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9016",
    "framework_tags": [
        "NIST-800-53-AU-2", "NIST-800-53-AU-12", "NIST-800-53-AU-3", "NIST-CSF-2.0-DE.CM-03",
        "PCI-DSS-4.0-10.2.1", "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5", "CIS-CSC-8-8.2",
        "CIS-CSC-8-8.5", "ISO-27001-2022-A.8.15", "SOC2-CC7.2", "HIPAA-164.312(b)",
        "DISA-STIG", "MITRE-ATTCK-T1562.002",
    ],
    "references": [
        {"title": "Microsoft: Audit Policy Recommendations",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations"},
        {"title": "Microsoft: Advanced security audit policy settings",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings"},
        {"title": "Microsoft: Audit: Force audit policy subcategory settings to override audit policy category settings",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-force-audit-policy-subcategory-settings-to-override"},
        {"title": "MITRE ATT&CK T1562.002: Impair Defenses: Disable Windows Event Logging",
         "url": "https://attack.mitre.org/techniques/T1562/002/"},
    ],
    "description": (
        "The effective Group Policy of a domain controller does not audit all security event "
        "subcategories needed to detect attacks on Active Directory (credential validation, "
        "Kerberos, account and group management, directory service access and changes, policy "
        "changes, sensitive privilege use, logon and process creation), or configures no audit "
        "policy at all."
    ),
    "remediation": (
        "In a GPO linked to the Domain Controllers OU configure Computer Configuration > Policies > "
        "Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit "
        "Policies: Account Logon (Credential Validation, Kerberos Authentication Service, Kerberos "
        "Service Ticket Operations: Success and Failure); Account Management (Computer Account "
        "Management, Security Group Management, Other Account Management Events: Success; User "
        "Account Management: Success and Failure); DS Access (Directory Service Access: Failure "
        "or both; Directory Service Changes: Success); Policy Change (Audit Policy Change, "
        "Authentication Policy Change: Success); Privilege Use (Sensitive Privilege Use: Success "
        "and Failure); Logon/Logoff (Logon: Success and Failure; Special Logon: Success); Detailed "
        "Tracking (Process Creation: Success, with command line logging). Keep 'Audit: Force audit "
        "policy subcategory settings ... to override audit policy category settings' Enabled. "
        "Directory Service Changes also needs SACLs on the directory (present by default on the "
        "domain root). Run gpupdate /force and verify with auditpol /get /category:*. Make sure "
        "the Security log is large enough and forwarded to a SIEM."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH dc AS (
            SELECT c.object_guid AS dc_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current, c.object_guid::text) AS dc_name,
                   c.dns_hostname, c.operating_system
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                          WHERE s.client_id = %(client_id)s AND s.read_status = 'ok')
        ),
        unreadable AS (
            SELECT x.dc_guid,
                   jsonb_agg(jsonb_build_object('gpo_guid', x.gpo_guid, 'display_name', x.display_name,
                                                'read_status', x.read_status)
                             ORDER BY x.gpo_guid) AS gpos
            FROM (
                SELECT DISTINCT a.dc_guid, a.gpo_guid, g.display_name,
                       COALESCE(s.read_status, 'not_collected') AS read_status
                FROM v_gpo_dc_application a
                LEFT JOIN ad_gpo_sysvol s
                  ON s.client_id = a.client_id AND s.gpo_object_guid = a.gpo_guid
                LEFT JOIN ad_gpo g
                  ON g.client_id = a.client_id AND g.object_guid = a.gpo_guid AND g.valid_to IS NULL
                WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
                  AND s.read_status IS DISTINCT FROM 'ok'
            ) x
            GROUP BY x.dc_guid
        ),
        req (ord, sub_name, sub_guid, req_bits, legacy_key) AS (
            VALUES
                (1,  'Credential Validation',              '0cce923f-69ae-11d9-bed3-505054503030', 3, 'auditaccountlogon'),
                (2,  'Kerberos Authentication Service',    '0cce9242-69ae-11d9-bed3-505054503030', 3, 'auditaccountlogon'),
                (3,  'Kerberos Service Ticket Operations', '0cce9240-69ae-11d9-bed3-505054503030', 3, 'auditaccountlogon'),
                (4,  'Computer Account Management',        '0cce9236-69ae-11d9-bed3-505054503030', 1, 'auditaccountmanage'),
                (5,  'Security Group Management',          '0cce9237-69ae-11d9-bed3-505054503030', 1, 'auditaccountmanage'),
                (6,  'User Account Management',            '0cce9235-69ae-11d9-bed3-505054503030', 3, 'auditaccountmanage'),
                (7,  'Other Account Management Events',    '0cce923a-69ae-11d9-bed3-505054503030', 1, 'auditaccountmanage'),
                (8,  'Directory Service Access',           '0cce923b-69ae-11d9-bed3-505054503030', 2, 'auditdsaccess'),
                (9,  'Directory Service Changes',          '0cce923c-69ae-11d9-bed3-505054503030', 1, 'auditdsaccess'),
                (10, 'Audit Policy Change',                '0cce922f-69ae-11d9-bed3-505054503030', 1, 'auditpolicychange'),
                (11, 'Authentication Policy Change',       '0cce9230-69ae-11d9-bed3-505054503030', 1, 'auditpolicychange'),
                (12, 'Sensitive Privilege Use',            '0cce9228-69ae-11d9-bed3-505054503030', 3, 'auditprivilegeuse'),
                (13, 'Logon',                              '0cce9215-69ae-11d9-bed3-505054503030', 3, 'auditlogonevents'),
                (14, 'Special Logon',                      '0cce921b-69ae-11d9-bed3-505054503030', 1, 'auditlogonevents'),
                (15, 'Process Creation',                   '0cce922b-69ae-11d9-bed3-505054503030', 1, 'auditprocesstracking')
        ),
        eff AS (
            SELECT e.dc_guid, e.source, lower(e.setting_key) AS k,
                   lower(regexp_replace(COALESCE(e.value_type, ''), '^\s*audit\s+', '', 'i')) AS sub_name_l,
                   e.setting_value, e.winning_gpo_guid,
                   COALESCE(g.display_name, e.winning_gpo_guid::text) AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]+\s*$'
                        THEN trim(e.setting_value)::int END AS num
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s
              AND ((e.source = 'audit' AND e.section = 'advanced_audit')
                   OR (e.source = 'security_template' AND e.section = 'Event Audit'))
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        mode AS (
            SELECT d.*, u.gpos AS unreadable_gpos,
                   CASE WHEN EXISTS (SELECT 1 FROM eff a WHERE a.dc_guid = d.dc_guid AND a.source = 'audit'
                                       AND (a.k ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                                            OR a.sub_name_l IN (SELECT lower(r.sub_name) FROM req r)))
                             THEN 'advanced'
                        WHEN EXISTS (SELECT 1 FROM eff l WHERE l.dc_guid = d.dc_guid
                                       AND l.source = 'security_template')
                             THEN 'legacy'
                        ELSE 'none' END AS policy_mode
            FROM dc d
            LEFT JOIN unreadable u ON u.dc_guid = d.dc_guid
        ),
        per_sub AS (
            SELECT m.dc_guid, r.ord, r.sub_name, r.req_bits, v.setting_value, v.num, v.gpo_name,
                   v.winning_gpo_guid, v.matched_key,
                   CASE WHEN v.matched_key IS NULL THEN 'missing'
                        WHEN v.num IS NOT NULL AND (v.num & r.req_bits) = r.req_bits THEN 'ok'
                        ELSE 'insufficient' END AS state
            FROM mode m
            CROSS JOIN req r
            LEFT JOIN LATERAL (
                SELECT x.* FROM (
                SELECT a.k AS matched_key, a.setting_value, a.num, a.gpo_name, a.winning_gpo_guid
                FROM eff a
                WHERE m.policy_mode = 'advanced' AND a.dc_guid = m.dc_guid AND a.source = 'audit'
                  AND (a.k = r.sub_guid OR a.sub_name_l = lower(r.sub_name))
                UNION ALL
                SELECT l.k, l.setting_value, l.num, l.gpo_name, l.winning_gpo_guid
                FROM eff l
                WHERE m.policy_mode = 'legacy' AND l.dc_guid = m.dc_guid AND l.source = 'security_template'
                  AND l.k = r.legacy_key
                ) x
                ORDER BY (x.matched_key = r.sub_guid) DESC, x.matched_key
                LIMIT 1
            ) v ON TRUE
            WHERE m.policy_mode <> 'none'
        ),
        agg AS (
            SELECT p.dc_guid,
                   count(*) FILTER (WHERE p.state = 'missing') AS n_missing,
                   count(*) FILTER (WHERE p.state = 'insufficient') AS n_insufficient,
                   string_agg(p.sub_name, ', ' ORDER BY p.ord) FILTER (WHERE p.state = 'missing') AS missing_list,
                   string_agg(p.sub_name || ' (has ' ||
                              CASE p.num WHEN 0 THEN 'no auditing' WHEN 1 THEN 'success'
                                         WHEN 2 THEN 'failure' WHEN 3 THEN 'success and failure'
                                         ELSE 'unrecognised value ' || COALESCE(p.setting_value, '(empty)') END
                              || ', needs ' ||
                              CASE p.req_bits WHEN 1 THEN 'success' WHEN 2 THEN 'failure'
                                              ELSE 'success and failure' END || ')',
                              ', ' ORDER BY p.ord) FILTER (WHERE p.state = 'insufficient') AS insufficient_list,
                   jsonb_agg(jsonb_build_object(
                       'subcategory', p.sub_name,
                       'required', CASE p.req_bits WHEN 1 THEN 'success' WHEN 2 THEN 'failure'
                                                   ELSE 'success and failure' END,
                       'configured_value', p.setting_value,
                       'matched_setting', p.matched_key,
                       'winning_gpo_guid', p.winning_gpo_guid,
                       'winning_gpo_name', p.gpo_name,
                       'state', p.state) ORDER BY p.ord) AS subcategories
            FROM per_sub p
            GROUP BY p.dc_guid
        ),
        res AS (
            SELECT m.*, a.n_missing, a.n_insufficient, a.missing_list, a.insufficient_list, a.subcategories,
                   CASE WHEN m.policy_mode = 'none' THEN 'warn'
                        WHEN a.n_insufficient > 0 THEN 'fail'
                        WHEN a.n_missing > 0 AND m.unreadable_gpos IS NULL THEN 'fail'
                        WHEN a.n_missing > 0 THEN 'warn'
                        ELSE 'pass' END AS status
            FROM mode m
            LEFT JOIN agg a ON a.dc_guid = m.dc_guid
        )
        SELECT
            r.status,
            r.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            CASE WHEN r.policy_mode = 'none' THEN
                'Domain controller ' || r.dc_name || ': audit policy is not enforced by Group Policy -- '
                    || 'no applying GPO configures advanced audit policy or legacy [Event Audit] categories '
                    || '(the DC may have a local audit policy that cannot be seen)'
            ELSE
                'Domain controller ' || r.dc_name || ': '
                    || CASE WHEN r.policy_mode = 'advanced' THEN 'advanced' ELSE 'legacy' END
                    || ' audit policy does not cover '
                    || (r.n_missing + r.n_insufficient)::text || ' of 15 required subcategories -- '
                    || concat_ws('; ',
                           CASE WHEN r.missing_list IS NOT NULL THEN 'not audited: ' || r.missing_list END,
                           CASE WHEN r.insufficient_list IS NOT NULL THEN 'incomplete: ' || r.insufficient_list END)
            END
            || CASE WHEN r.unreadable_gpos IS NOT NULL AND (r.policy_mode = 'none' OR r.n_missing > 0)
                    THEN '; uncertain: some GPOs applying to this DC could not be read from SYSVOL'
                    ELSE '' END AS summary,
            jsonb_build_object(
                'domain_controller', r.dc_name,
                'dns_hostname', r.dns_hostname,
                'operating_system', r.operating_system,
                'policy_evaluated', r.policy_mode,
                'missing_count', r.n_missing,
                'insufficient_count', r.n_insufficient,
                'subcategories', COALESCE(r.subcategories, '[]'::jsonb),
                'unreadable_applying_gpos', COALESCE(r.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM res r
        WHERE r.status <> 'pass'
    """,
}
