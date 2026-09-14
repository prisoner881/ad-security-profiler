"""
Plugin 10009: Entra Connect Directory Synchronization Account Exposure

Derived from CISA advisory AA26-237A (2026-08-25). In the Water and
Wastewater Systems assessment, the red team recovered cleartext
credentials for both the on-premises directory synchronization account
and its cloud counterpart by dumping configuration from the Entra
Connect server, and used them to move between the on-premises domain
and the cloud tenant.

The on-premises sync account (conventionally MSOL_<hex>, or AAD_<hex>
on older DirSync deployments) is granted directory replication rights
-- DS-Replication-Get-Changes and DS-Replication-Get-Changes-All -- on
the domain root by design, because password hash synchronization
requires them. That means it is a Tier 0 principal with standing
DCSync capability, created automatically by an installation wizard,
named unhelpfully, and usually excluded from the privileged-account
review processes that cover Domain Admins. Plugin 5001 deliberately
does not flag it, because its replication rights are expected; this
plugin exists to make the opposite point, which is that "expected" is
not the same as "unmonitored."

What is checkable from LDAP is the account's credential hygiene: how
long the password has gone unrotated, whether the account carries SPNs
(which would make a Tier 0 DCSync principal Kerberoastable), and
whether it is disabled but still holding replication rights. What is
not checkable from LDAP is the security posture of the Entra Connect
server itself -- and that host is where the credential actually leaks
from, so the remediation addresses it explicitly.
"""

PLUGIN = {
    "plugin_id": 10009,
    "category": "Hybrid Identity",
    "name": "Entra Connect Directory Synchronization Account Exposure",
    "version": "1.0",
    "revision_date": "2026-09-02",
    "remediation": (
        "Treat this account as Tier 0 and the Entra Connect server as "
        "a Tier 0 asset, on par with a domain controller -- it holds a "
        "credential with directory replication rights, so anyone with "
        "administrative access to that host has a path to the entire "
        "domain database. Concretely: restrict local administrator "
        "rights on the sync server to the same population that "
        "administers DCs; do not allow it to be managed by general "
        "server-administration groups, and do not co-locate it with "
        "other roles. Rotate the sync account credential on a defined "
        "schedule -- Entra Connect exposes "
        "Add-ADSyncADDSConnectorAccount to change it without "
        "reinstalling. Where the Entra Connect version supports it, "
        "migrate from a static-password account to a group Managed "
        "Service Account (gMSA), which removes the static secret "
        "entirely; new installations default to this and existing ones "
        "can be converted. Confirm the account has no "
        "servicePrincipalName registered: an account with standing "
        "DCSync rights and an SPN is directly Kerberoastable, which "
        "converts a domain-user foothold into domain compromise. "
        "Deny interactive and network logon rights for the account "
        "anywhere except the sync server, and alert on any "
        "authentication by it from another source. Finally, if this "
        "account is reported as disabled, do not treat that as safe -- "
        "it retains its replication rights and can be re-enabled (see "
        "plugin 1042)."
    ),
    "control_id": "HYBRID-409",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1003.006", "MITRE-ATTCK-T1078.002",
                       "MITRE-ATTCK-T1552.001"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Identifies the on-premises Microsoft Entra Connect (or legacy "
        "DirSync) directory synchronization account and reports its "
        "credential hygiene. This account is granted DCSync-equivalent "
        "replication rights on the domain root by design, making it a "
        "Tier 0 principal, but it is created automatically by an "
        "installation wizard under an opaque machine-generated name "
        "and is routinely omitted from privileged-account review. "
        "CISA's AA26-237A red team assessment recovered this "
        "credential in cleartext from the Entra Connect server and "
        "used it to move between the on-premises domain and the cloud "
        "tenant. Flags the account when its password has not been "
        "rotated within a year, when it carries a "
        "servicePrincipalName (making a standing-DCSync principal "
        "Kerberoastable), or when it is disabled yet still holds "
        "replication rights. Severity is raised when the account's "
        "replication rights are directly confirmed against the "
        "collected domain root ACL."
    ),
    "base_severity": "high",
    "query": """
        WITH sync_accounts AS (
            SELECT u.*, do2.dn_current, do2.object_sid
            FROM ad_user u
            JOIN directory_object do2
                ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND (
                    u.sam_account_name LIKE 'MSOL_%%'
                 OR u.sam_account_name LIKE 'AAD_%%'
                 OR u.sam_account_name LIKE 'ADSyncMSA%%'
                 OR u.description ILIKE '%%Azure AD Connect%%'
                 OR u.description ILIKE '%%Entra Connect%%'
                 OR u.description ILIKE '%%directory synchronization%%'
              )
        ),
        replication_holders AS (
            SELECT DISTINCT a.trustee_sid
            FROM acl_edge a
            JOIN ad_domain d
                ON d.object_guid = a.object_guid AND d.valid_to IS NULL
                AND d.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                          '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
        )
        SELECT
            'fail' AS status,
            sa.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN COALESCE(array_length(sa.service_principal_names, 1), 0) > 0
                    THEN 'critical'
                WHEN rh.trustee_sid IS NOT NULL THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            'Directory synchronization account "' || sa.sam_account_name
                || '" (Tier 0, holds directory replication rights by design) '
                || CASE
                       WHEN COALESCE(array_length(sa.service_principal_names, 1), 0) > 0
                           THEN 'has a servicePrincipalName registered and is therefore '
                                'Kerberoastable'
                       WHEN sa.is_enabled IS FALSE
                           THEN 'is disabled but retains its replication rights'
                       WHEN sa.pwd_last_set IS NULL
                           THEN 'has no recorded password rotation date'
                       ELSE 'has not had its password rotated in '
                            || EXTRACT(DAY FROM now() - sa.pwd_last_set)::int || ' days'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', sa.sam_account_name,
                'distinguished_name', sa.dn_current,
                'description', sa.description,
                'is_enabled', sa.is_enabled,
                'replication_rights_confirmed_on_domain_root',
                    rh.trustee_sid IS NOT NULL,
                'has_service_principal_names',
                    COALESCE(array_length(sa.service_principal_names, 1), 0) > 0,
                'service_principal_names', sa.service_principal_names,
                'pwd_last_set', sa.pwd_last_set,
                'password_age_days',
                    CASE WHEN sa.pwd_last_set IS NULL THEN NULL
                         ELSE EXTRACT(DAY FROM now() - sa.pwd_last_set)::int END,
                'pwd_never_expires', sa.pwd_never_expires,
                'admin_count', sa.admin_count,
                'last_logon_timestamp', sa.last_logon_timestamp,
                'when_created', sa.when_created
            ) AS detail
        FROM sync_accounts sa
        LEFT JOIN replication_holders rh ON rh.trustee_sid = sa.object_sid
        WHERE COALESCE(array_length(sa.service_principal_names, 1), 0) > 0
           OR sa.is_enabled IS FALSE
           OR sa.pwd_last_set IS NULL
           OR sa.pwd_last_set < now() - interval '365 days'
    """,
}
