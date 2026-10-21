"""
Plugin 4037: Service Accounts Not Covered by a Strong Fine-Grained Password Policy

Reports enabled user accounts that carry a service principal name -- service
accounts, and Kerberoastable by any domain user -- whose effective password
policy allows a password shorter than 20 characters. One row per policy
source (the PSO or the domain default policy), listing the accounts.

Why it matters: any authenticated user can request a service ticket for an
SPN-bearing user account and crack it offline (Kerberoasting, MITRE ATT&CK
T1558.003). The ticket is encrypted with a key derived from the password,
so password length is the only defence that scales: Microsoft and ANSSI
recommend at least 20-25 random characters for such accounts, enforced by
a fine-grained password policy (PSO) applied to a group of service
accounts (PingCastle A-NoServicePolicy). Group managed service accounts
(gMSA, 120-character random passwords) avoid the problem entirely and are
not reported.

Effective policy: Microsoft's resolution order -- a PSO linked to the user
directly wins; otherwise the lowest-precedence PSO among the global security
groups the user is an effective member of; otherwise the domain policy (as
plugin 4002).

Severity ('warn'): medium when at least one listed account is privileged
(v_privileged_principal); low otherwise. krbtgt is excluded.
"""

PLUGIN = {
    "plugin_id": 4037,
    "category": "Domain",
    "name": "Service Accounts Not Covered by a Strong Fine-Grained Password Policy",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "DOMAIN-4037",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.6",
        "PCI-DSS-4.0-8.6.3",
        "CIS-CSC-8-5.2",
        "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1558.003",
    ],
    "references": [
        {"title": "Microsoft: Configure fine-grained password policies (AD DS)",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies"},
        {"title": "Microsoft: Group Managed Service Accounts overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"},
        {"title": "PingCastle health check rules (A-NoServicePolicy)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
    ],
    "description": (
        "Enabled user accounts with a service principal name (Kerberoastable "
        "service accounts) have an effective password policy whose minimum "
        "length is under 20 characters. Medium when a privileged account is "
        "among them, low otherwise."
    ),
    "remediation": (
        "Create a fine-grained password policy with a minimum length of 20 "
        "(25 or more preferred) and apply it to a global security group "
        "holding the service accounts (New-ADFineGrainedPasswordPolicy; "
        "Add-ADFineGrainedPasswordPolicySubject). Then reset each account's "
        "password to a long random value -- the policy only applies at the "
        "next change. Better still, move the services to group managed "
        "service accounts."
    ),
    "base_severity": "low",
    "query": """
        WITH domain_default AS (
            SELECT d.object_guid AS domain_guid, d.pwd_policy_min_length AS min_length
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        active_fgpps AS (
            SELECT f.object_guid AS pso_guid, f.policy_name, f.precedence, f.min_pwd_length
            FROM ad_fgpp f
            WHERE f.client_id = %(client_id)s AND f.valid_to IS NULL
              AND f.min_pwd_length IS NOT NULL
        ),
        svc AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name, u.pwd_last_set,
                   cardinality(u.service_principal_names) AS spn_count
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.is_enabled
              AND COALESCE(cardinality(u.service_principal_names), 0) > 0
              AND COALESCE(o.object_sid::text, '') NOT LIKE '%%-502'
        ),
        direct_assignments AS (
            SELECT e.target_guid AS user_guid, af.pso_guid, af.policy_name, af.precedence, af.min_pwd_length
            FROM fgpp_applies_to_edge e
            JOIN active_fgpps af ON af.pso_guid = e.pso_guid
            JOIN svc s ON s.object_guid = e.target_guid
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        ),
        group_assignments AS (
            SELECT vem.member_guid AS user_guid, af.pso_guid, af.policy_name, af.precedence, af.min_pwd_length
            FROM fgpp_applies_to_edge e
            JOIN active_fgpps af ON af.pso_guid = e.pso_guid
            JOIN ad_group g ON g.object_guid = e.target_guid AND g.client_id = e.client_id AND g.valid_to IS NULL
                           AND (g.group_type & 2) <> 0 AND g.group_type < 0
            JOIN v_effective_group_membership vem ON vem.group_guid = e.target_guid AND vem.client_id = e.client_id
            JOIN svc s ON s.object_guid = vem.member_guid
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        ),
        best_direct AS (
            SELECT DISTINCT ON (user_guid) user_guid, pso_guid, policy_name, min_pwd_length
            FROM direct_assignments
            ORDER BY user_guid, precedence ASC, pso_guid ASC
        ),
        best_group AS (
            SELECT DISTINCT ON (user_guid) user_guid, pso_guid, policy_name, min_pwd_length
            FROM group_assignments
            ORDER BY user_guid, precedence ASC, pso_guid ASC
        ),
        priv AS (
            SELECT DISTINCT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
        ),
        eff AS (
            SELECT s.*,
                   COALESCE(bd.pso_guid, bg.pso_guid, dd.domain_guid) AS source_guid,
                   COALESCE(bd.policy_name, bg.policy_name, 'Domain Default Policy') AS source_name,
                   COALESCE(bd.min_pwd_length, bg.min_pwd_length, dd.min_length) AS min_length,
                   (pr.object_guid IS NOT NULL) AS privileged
            FROM svc s
            CROSS JOIN domain_default dd
            LEFT JOIN priv pr ON pr.object_guid = s.object_guid
            LEFT JOIN best_direct bd ON bd.user_guid = s.object_guid
            LEFT JOIN best_group bg ON bg.user_guid = s.object_guid
        )
        SELECT
            'warn' AS status,
            e.source_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(e.privileged) THEN 'medium' ELSE 'low' END AS fd_severity,
            count(*) || ' service account(s) with an SPN have an effective minimum password length of '
                || CASE WHEN min(e.min_length) = max(e.min_length) THEN min(e.min_length)::text
                        ELSE min(e.min_length) || '-' || max(e.min_length) END
                || ' characters via "' || e.source_name || '" (20 or more recommended)'
                || CASE WHEN bool_or(e.privileged)
                        THEN ', including privileged account(s): '
                             || string_agg(e.sam_account_name, ', ' ORDER BY lower(e.sam_account_name))
                                    FILTER (WHERE e.privileged)
                        ELSE '' END AS summary,
            jsonb_build_object(
                'policy_source', e.source_name,
                'effective_min_length', min(e.min_length),
                'recommended_min_length', 20,
                'account_count', count(*),
                'accounts', jsonb_agg(jsonb_build_object(
                    'sam_account_name', e.sam_account_name, 'privileged', e.privileged,
                    'spn_count', e.spn_count, 'pwd_last_set', e.pwd_last_set)
                    ORDER BY lower(e.sam_account_name))
            ) AS detail
        FROM eff e
        WHERE e.min_length IS NOT NULL AND e.min_length < 20
        GROUP BY e.source_guid, e.source_name
    """,
}
