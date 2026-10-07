"""
Plugin 4009: Machine Account Quota Allows Unprivileged Users to Join Computers to the Domain

ms-DS-MachineAccountQuota defaults to 10 when unset -- meaning every
authenticated domain user can join up to 10 computers to the domain with
no special rights at all. A well-documented, commonly-abused default in
real-world penetration testing, closely tied to relay-based computer
account creation and subsequent lateral movement. Confirmed 0 is the
correct hardened value directly from Microsoft's own community guidance,
after finding and resolving a real contradiction across sources during
research for this plugin.

If unset in AD, LDAP simply won't return this attribute at all, meaning
this project's own collected value will be NULL -- treated here as 10
(the documented default), not skipped, via COALESCE.

[v1.3] The detail now notes that the quota is only usable by principals
holding SeMachineAccountPrivilege ("Add workstations to domain", granted
to Authenticated Users by the Default Domain Controllers Policy). GPO
content is not collected, so a domain that has removed that grant is
still reported; the note tells the reader to check it.

[v1.4] When SYSVOL has been collected (adprofiler.py --sysvol), the
effective SeMachineAccountPrivilege assignment on the domain controllers
(winning [Privilege Rights] value per DC, v_dc_effective_gpo_setting, as
plugin 9015 reads it) decides the finding:
- not set by any GPO applying to one or more DCs: the Windows default
  (Authenticated Users) applies there unless changed locally -> medium
  warn, as before, saying so;
- granted to a broad principal on any DC (Authenticated Users, Everyone,
  Users, Domain Users of any domain) -> medium warn, as before;
- granted only to named principals -> low warn: the quota is usable only
  by those principals, listed in the summary and detail;
- granted to nobody -> no finding (the quota cannot be used).
Without SYSVOL the v1.3 behaviour and note are kept. detail adds
right_assignment ('not_collected', 'not_configured', 'broad',
'restricted') and add_workstations_principals.
"""

PLUGIN = {
    "plugin_id": 4009,
    "category": "Domain",
    "name": "Machine Account Quota Allows Unprivileged Users to Join Computers to the Domain",
    "version": "1.4",
    "revision_date": "2026-10-07",
    "remediation": (
        "Set ms-DS-MachineAccountQuota to 0 "
        "(`Set-ADDomain -Identity <domain> -Replace "
        "@{\"ms-DS-MachineAccountQuota\"=\"0\"}`). Confirmed directly "
        "against Microsoft's own community guidance: this is the "
        "correct hardened value, not a misconfiguration -- it does not "
        "affect existing computer accounts, and Domain Admins and "
        "anyone explicitly delegated \"Create Computer Objects\" rights "
        "remain unaffected regardless of this value. If any automated "
        "process relies on non-admin users joining machines to the "
        "domain, delegate that specific right to a dedicated account or "
        "group instead of relying on the domain-wide quota."
    ),
    "control_id": "POLICY-009",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-2",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1136.002",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-MachineAccountQuota attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota"},
    ],
    "description": (
        "ms-DS-MachineAccountQuota defaults to 10 when unset in AD -- "
        "meaning every authenticated domain user can join up to 10 "
        "computers to the domain with no special rights at all. This is "
        "a well-documented, commonly-abused default in real-world "
        "penetration testing: attackers can create machine accounts "
        "they fully control using only regular domain user credentials "
        "(no real computer hardware needed), then use those accounts "
        "for authentication, relay-based attacks, and further lateral "
        "movement. Worth noting for completeness: during research for "
        "this plugin, a direct contradiction was found across sources "
        "about what a value of 0 actually means. Resolved based on the "
        "weight of evidence -- six independent sources including "
        "Microsoft's own community support forum, which directly and "
        "unambiguously confirms 0 is the hardening fix, not a "
        "regression. The quota only applies to principals that hold "
        "SeMachineAccountPrivilege (\"Add workstations to domain\", "
        "Authenticated Users by default in the Default Domain "
        "Controllers Policy). With SYSVOL collected the plugin reads that "
        "assignment from the domain controllers' effective Group Policy: "
        "medium when a broad group holds it or no GPO sets it, low when "
        "only named principals hold it, no finding when nobody does. "
        "Without SYSVOL, check that assignment if this finding appears "
        "on a domain that has already removed it."
    ),
    "base_severity": "medium",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        -- [v1.4] effective "Add workstations to domain" per DC
        eff AS (
            SELECT e.dc_guid, e.setting_value
            FROM v_dc_effective_gpo_setting e
            WHERE e.client_id = %(client_id)s
              AND e.source = 'security_template'
              AND lower(e.section) = 'privilege rights'
              AND lower(e.setting_key) = 'semachineaccountprivilege'
        ),
        entry AS (
            SELECT DISTINCT btrim(x) AS raw_entry
            FROM eff e
            CROSS JOIN LATERAL unnest(string_to_array(COALESCE(e.setting_value, ''), ',')) AS x
            WHERE btrim(x) <> ''
        ),
        named AS (
            SELECT en.raw_entry,
                   CASE WHEN left(en.raw_entry, 1) = '*' THEN upper(substr(en.raw_entry, 2)) END AS sid,
                   lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1))) AS short_name
            FROM entry en
        ),
        principals AS (
            SELECT n.raw_entry,
                   COALESCE(
                       CASE n.sid WHEN 'S-1-5-11' THEN 'Authenticated Users' WHEN 'S-1-1-0' THEN 'Everyone'
                                  WHEN 'S-1-5-32-545' THEN 'Users' WHEN 'S-1-5-32-544' THEN 'Administrators' END,
                       (SELECT o.sam_account_name FROM directory_object o
                         WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
                           AND o.object_sid::text = n.sid AND o.sam_account_name IS NOT NULL
                         ORDER BY o.object_guid LIMIT 1),
                       CASE WHEN n.sid IS NOT NULL THEN n.sid ELSE n.raw_entry END) AS display_name,
                   COALESCE(n.sid IN ('S-1-5-11', 'S-1-1-0', 'S-1-5-32-545')
                            OR n.sid ~ '^S-1-5-21-[0-9-]+-513$', false)
                   OR (n.sid IS NULL AND n.short_name IN ('authenticated users', 'everyone',
                                                         'users', 'domain users')) AS broad
            FROM named n
        ),
        assessment AS (
            SELECT CASE WHEN NOT sv.collected THEN 'not_collected'
                        -- a DC with no GPO setting keeps the Windows default
                        WHEN NOT EXISTS (SELECT 1 FROM eff)
                             OR EXISTS (SELECT 1 FROM ad_computer c
                                         WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
                                           AND c.is_domain_controller IS TRUE
                                           AND NOT EXISTS (SELECT 1 FROM eff e WHERE e.dc_guid = c.object_guid))
                             THEN 'not_configured'
                        WHEN EXISTS (SELECT 1 FROM principals p WHERE p.broad) THEN 'broad'
                        WHEN EXISTS (SELECT 1 FROM principals) THEN 'restricted'
                        ELSE 'nobody' END AS right_assignment,
                   (SELECT string_agg(p.display_name, ', ' ORDER BY lower(p.display_name)) FROM principals p)
                       AS principals_text,
                   (SELECT jsonb_agg(jsonb_build_object('entry', p.raw_entry, 'name', p.display_name,
                                                        'broad_principal', p.broad)
                                     ORDER BY lower(p.display_name), p.raw_entry) FROM principals p)
                       AS principal_list
            FROM sysvol sv
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.right_assignment = 'restricted' THEN 'low' ELSE 'medium' END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || CASE WHEN a.right_assignment = 'restricted'
                        THEN ' lets the principals granted "Add workstations to domain" by Group Policy ('
                             || a.principals_text || ') join up to '
                        ELSE ' allows any authenticated user to join up to ' END
                || COALESCE(d.machine_account_quota, 10) || ' computer(s) to the domain '
                '(ms-DS-MachineAccountQuota)' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'machine_account_quota', COALESCE(d.machine_account_quota, 10),
                'was_unset_in_ad', d.machine_account_quota IS NULL,
                'right_assignment', a.right_assignment,
                'add_workstations_principals', a.principal_list,
                'note', CASE a.right_assignment
                    WHEN 'not_collected' THEN
                        'Exploitable only by principals granted SeMachineAccountPrivilege '
                        '("Add workstations to domain"; Authenticated Users by default in the '
                        'Default Domain Controllers Policy). Not verified: SYSVOL was not collected '
                        '(adprofiler.py --sysvol).'
                    WHEN 'not_configured' THEN
                        'No GPO applying to one or more domain controllers sets "Add workstations to '
                        'domain", so the Windows default (Authenticated Users) applies there unless it '
                        'was changed locally.'
                    WHEN 'broad' THEN
                        '"Add workstations to domain" is granted to a broad group by the domain '
                        'controllers'' effective Group Policy.'
                    ELSE
                        '"Add workstations to domain" is limited by Group Policy to the listed '
                        'principals; only they can use the quota.'
                END
            ) AS detail
        FROM ad_domain d
        CROSS JOIN assessment a
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND COALESCE(d.machine_account_quota, 10) > 0
          AND a.right_assignment <> 'nobody'
    """,
}
