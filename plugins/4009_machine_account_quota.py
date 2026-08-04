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
"""

PLUGIN = {
    "plugin_id": 4009,
    "category": "Domain",
    "name": "Machine Account Quota Allows Unprivileged Users to Join Computers to the Domain",
    "version": "1.1",
    "revision_date": "2026-07-15",
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
    "framework_tags": [],
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
        "regression."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' allows any authenticated user to join up to '
                || COALESCE(d.machine_account_quota, 10) || ' computer(s) to the domain '
                '(ms-DS-MachineAccountQuota)' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'machine_account_quota', COALESCE(d.machine_account_quota, 10),
                'was_unset_in_ad', d.machine_account_quota IS NULL
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND COALESCE(d.machine_account_quota, 10) > 0
    """,
}
