"""
Plugin 2001: Unconstrained Kerberos Delegation on a Non-DC Computer

Unconstrained delegation is normal and required on domain controllers --
this plugin deliberately excludes them. On any other computer, it means a
compromised machine can extract cached TGTs of anyone who authenticates
to it, including a Domain Admin, and impersonate them anywhere in the
domain. One of the most well-known real-world AD attack primitives.
"""

PLUGIN = {
    "plugin_id": 2001,
    "category": "Computer Accounts",
    "name": "Unconstrained Kerberos Delegation on Non-DC Computer",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Migrate to constrained delegation, or better, resource-based "
        "constrained delegation -- both limit impersonation to "
        "explicitly-defined target services rather than allowing full TGT "
        "reuse against any service in the domain. If unconstrained "
        "delegation is genuinely required (rare, typically legacy "
        "scenarios like old IIS/SQL configurations), ensure any "
        "privileged account that might authenticate to this machine is "
        "itself protected (Protected Users membership or the \"account is "
        "sensitive and cannot be delegated\" flag), and restrict network "
        "reachability to this machine as tightly as possible in the "
        "meantime."
    ),
    "control_id": "DELEG-003",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
        {"title": "DISA Active Directory Domain STIG V-243478: Domain-joined systems (excluding domain controllers) must not be configured for unconstrained delegation",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243478"},
    ],
    "description": (
        "Unconstrained delegation on a domain controller is normal and "
        "required for Kerberos to function -- this check deliberately "
        "excludes domain controllers. On any other computer, unconstrained "
        "delegation means a compromised machine can extract the cached "
        "Ticket Granting Tickets of anyone who has authenticated to it -- "
        "including, via forced-authentication techniques, a Domain "
        "Controller itself -- and impersonate them anywhere in the domain. "
        "This is one of the most well-known and commonly abused real-world "
        "AD attack primitives (the same underlying mechanism already "
        "covered for user accounts by plugin 1010, applied here to "
        "computer objects, which is where it is most commonly found in "
        "practice -- legacy web/SQL servers configured this way for "
        "convenience). "
        "NOT downgraded when disabled: delegation settings persist regardless of account state and reactivate immediately if the account is re-enabled."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243478' AS stig_reference,
            'critical' AS tool_severity,
            'PingCastle: unconstrained delegation rule -- "Kerberos unconstrained '
                'delegation allows a service to reuse a user''s Ticket Granting '
                'Ticket (TGT) to authenticate to any service in the domain... the '
                'attacker can escalate privileges and compromise the entire domain."' AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' has unconstrained Kerberos delegation enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.unconstrained_delegation
          AND NOT c.is_domain_controller
    """,
}
