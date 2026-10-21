"""
Plugin 2043: Constrained Delegation to a Domain Controller Service

Reports user and computer accounts configured for Kerberos constrained
delegation (msDS-AllowedToDelegateTo) WITHOUT protocol transition whose
target is a service on a domain controller (ldap/, cifs/, host/, ... on a
DC computer object), or krbtgt. Accounts with protocol transition
(TRUSTED_TO_AUTH_FOR_DELEGATION) are reported by plugins 1020 (users) and
2002 (computers); domain controllers themselves are not reported. One row
per delegating account (object_guid = that account).

Why it matters: the account can obtain service tickets to the DC's
services in the name of any user who authenticates to it (S4U2Proxy) --
including Domain Admins unless they are in Protected Users or marked
"sensitive and cannot be delegated". Delegation to ldap/ or cifs/ on a DC
is equivalent to DCSync or full control of the DC. Even without protocol
transition the account can be abused through resource-based constrained
delegation tricks (Elad Shamir, "Wagging the Dog"), so anyone who
compromises it compromises the domain (PingCastle P-DelegationDCa2d2).

Severity ('fail'): high; medium when the delegating account is disabled.
The detail lists the DC targets (and any other targets).

Data: delegation_edge (delegation_type 'constrained') resolved to
ad_computer, unresolved_delegation_target_edge for krbtgt/* SPNs,
user_account_control on ad_user / ad_computer.
"""

PLUGIN = {
    "plugin_id": 2043,
    "category": "Computer Accounts",
    "name": "Constrained Delegation to a Domain Controller Service",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "COMPUTER-2043",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1558",
        "MITRE-ATTCK-T1134",
    ],
    "references": [
        {"title": "Microsoft: Kerberos constrained delegation overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"},
        {"title": "Elad Shamir: Wagging the Dog -- Abusing Resource-Based Constrained Delegation",
         "url": "https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html"},
        {"title": "PingCastle health check rules (P-DelegationDCa2d2)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "A user or computer account has Kerberos constrained delegation "
        "(without protocol transition) to a service on a domain controller, "
        "or to krbtgt: it can impersonate users who authenticate to it "
        "against the DC, which amounts to control of the domain. High; "
        "medium when the account is disabled."
    ),
    "remediation": (
        "Remove the domain controller services from the account's "
        "msDS-AllowedToDelegateTo (Active Directory Users and Computers > "
        "Delegation tab, or Set-ADObject -Clear msDS-AllowedToDelegateTo). "
        "No application should need delegation to a DC's ldap, cifs or host "
        "service. Until it is removed, treat the account as Tier 0, and put "
        "administrative accounts in Protected Users or mark them sensitive "
        "and cannot be delegated."
    ),
    "base_severity": "high",
    "query": """
        WITH src AS (
            SELECT u.object_guid, 'user' AS kind, COALESCE(u.user_principal_name, u.sam_account_name) AS name,
                   u.sam_account_name, u.is_enabled, u.user_account_control
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND (COALESCE(u.user_account_control, 0) & 16777216) = 0
            UNION ALL
            SELECT c.object_guid, 'computer', COALESCE(c.dns_hostname, c.sam_account_name),
                   c.sam_account_name, c.is_enabled, c.user_account_control
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND NOT COALESCE(c.is_domain_controller, false)
              AND (COALESCE(c.user_account_control, 0) & 16777216) = 0
        ),
        targets AS (
            SELECT s.object_guid,
                   COALESCE(c.dns_hostname, o.sam_account_name, o.dn_current, de.target_guid::text) AS target_name,
                   COALESCE(c.is_domain_controller, false) AS is_dc
            FROM src s
            JOIN delegation_edge de
              ON de.source_guid = s.object_guid AND de.client_id = %(client_id)s
             AND de.valid_to IS NULL AND de.delegation_type = 'constrained'
            LEFT JOIN directory_object o
              ON o.object_guid = de.target_guid AND o.client_id = de.client_id
            LEFT JOIN ad_computer c
              ON c.object_guid = de.target_guid AND c.client_id = de.client_id AND c.valid_to IS NULL
            UNION
            SELECT s.object_guid, ue.target_spn, ue.target_spn ILIKE 'krbtgt/%%'
            FROM src s
            JOIN unresolved_delegation_target_edge ue
              ON ue.source_guid = s.object_guid AND ue.client_id = %(client_id)s AND ue.valid_to IS NULL
        ),
        agg AS (
            SELECT t.object_guid,
                   jsonb_agg(DISTINCT t.target_name ORDER BY t.target_name) FILTER (WHERE t.is_dc) AS dc_targets,
                   jsonb_agg(DISTINCT t.target_name ORDER BY t.target_name) AS all_targets,
                   string_agg(DISTINCT t.target_name, ', ' ORDER BY t.target_name) FILTER (WHERE t.is_dc) AS dc_text
            FROM targets t
            GROUP BY t.object_guid
            HAVING bool_or(t.is_dc)
        )
        SELECT
            'fail' AS status,
            s.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.is_enabled IS FALSE THEN 'medium' ELSE 'high' END AS fd_severity,
            CASE s.kind WHEN 'user' THEN 'User Account ' ELSE 'Computer Account ' END || s.name
                || ' has constrained delegation to a domain controller service ('
                || a.dc_text || ')'
                || CASE WHEN s.is_enabled IS FALSE THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'account_kind', s.kind,
                'sam_account_name', s.sam_account_name,
                'is_enabled', s.is_enabled,
                'user_account_control', s.user_account_control,
                'protocol_transition', false,
                'domain_controller_targets', a.dc_targets,
                'all_delegation_targets', a.all_targets
            ) AS detail
        FROM src s
        JOIN agg a ON a.object_guid = s.object_guid
    """,
}
