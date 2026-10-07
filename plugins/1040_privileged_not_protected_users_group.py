"""
Plugin 1040: Privileged Account Not a Member of the Protected Users Group

Protected Users (well-known RID 525, confirmed directly against
Microsoft's own documentation before building this) is a
non-configurable protection group introduced in Windows Server 2012
R2: membership disables NTLM authentication for the account, prevents
credential caching, disables Kerberos delegation entirely (unconstrained
and constrained alike), shortens the maximum Kerberos ticket lifetime,
and mandates strong (AES) encryption. It's a strictly stronger,
built-in alternative to manually managing several of these protections
individually.

Deliberately checks EVERY privileged account rather than building in
an "allow one exception" tolerance some guidance suggests (keeping one
admin account outside the group as a fallback in case of unexpected
lockout) -- that operational tradeoff is a legitimate decision for a
security team to make deliberately, not something this plugin should
silently decide on their behalf by suppressing findings.

[v1.2] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.3] Absorbs plugin 1015 (Privileged Account Not a Member of Protected
Users), now retired with superseded_by=1040. 1015 reported the same
accounts from ad_user.protected_users_member, a flag that only reflects
direct memberOf, so it also flagged accounts protected through a nested
group. This plugin now treats an account as a member if EITHER the
effective (nested) membership closure OR that direct-membership flag
says so -- the flag is a fallback for when the Protected Users group's
own membership edges were not collected, so no account becomes a
finding here that 1015 considered protected. Not merged: disabled
privileged accounts (plugin 1042's finding) and accounts privileged only
by a leftover admin_count=1 (plugin 1025). detail gains
protected_users_direct_flag. Summary and severity are unchanged.

[v1.4] detail gains has_spn (and spn_count) so service accounts -- which
Protected Users can break (no delegation, AES-only, no NTLM) -- can be
triaged separately. Selection, summary and severity are unchanged.

[v1.5] Entra Connect / Azure AD Connect sync accounts (MSOL_<hex> connector,
AAD_<hex> ADSync service account, or the installer's description) are no
longer reported: Microsoft does not support them in Protected Users (it can
break synchronization), and their exposure is reported by plugin 10009.
Plugin 1041 (cannot be delegated) still covers them.
"""

PLUGIN = {
    "plugin_id": 1040,
    "category": "User Accounts",
    "name": "Privileged Account Not a Member of the Protected Users Group",
    "version": "1.5",
    "revision_date": "2026-10-07",
    "remediation": (
        "Add this account to the built-in Protected Users group, "
        "provided the domain functional level is at least Windows "
        "Server 2012 R2 (required for DC-side enforcement; client-side "
        "protections work from Windows 8.1/Server 2012 R2 onward "
        "regardless of domain functional level). Test in a controlled "
        "way first -- Protected Users disables NTLM and all Kerberos "
        "delegation for the account, which can break legacy "
        "applications relying on either. Many organizations "
        "deliberately keep one break-glass admin account outside the "
        "group as an operational safety net; if that's the intent "
        "here, no action is needed for that specific account."
    ),
    "control_id": "USR-140",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "DISA-STIG",
        "DISA-STIG-V-243477",
        "MITRE-ATTCK-T1550.002",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: Protected Users Security Group",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"},
        {"title": "DISA Active Directory Domain STIG V-243477: User accounts with domain level administrative privileges must be members of the Protected Users group",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243477"},
        {"title": "PingCastle: Privileged Accounts rules -- P-ProtectedUsers",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A privileged account (effective member of an AdminSDHolder-"
        "protected group, or otherwise privileged via ACL/ownership --"
        " the same broadened definition used throughout this project) "
        "is not a member of the built-in Protected Users group (RID "
        "525). Membership disables NTLM, prevents credential caching, "
        "disables all Kerberos delegation, shortens maximum ticket "
        "lifetime, and mandates AES -- a strictly stronger built-in "
        "alternative to managing these protections individually."
    ),
    "base_severity": "medium",
    "query": """
        WITH privileged_check AS (
            -- [v1.2] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        protected_users_members AS (
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pu ON pu.object_guid = vem.group_guid AND pu.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s
              AND pu.object_sid LIKE '%%-525'
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243477' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is not a member of Protected Users' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'admin_count', u.admin_count,
                'is_enabled', u.is_enabled,
                'protected_users_direct_flag', u.protected_users_member,
                -- [v1.4] service-account triage
                'has_spn', COALESCE(cardinality(u.service_principal_names), 0) > 0,
                'spn_count', COALESCE(cardinality(u.service_principal_names), 0),
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN privileged_check pc ON pc.object_guid = u.object_guid
        LEFT JOIN protected_users_members pum ON pum.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND pum.object_guid IS NULL
          -- [v1.5] Entra Connect / Azure AD Connect sync accounts (MSOL_ connector,
          -- AAD_ / ADSync service account, or the installer's description) are
          -- service accounts: Protected Users can break synchronization (AES-only Kerberos, no NTLM, no credential caching). Their exposure is plugin 10009's
          -- finding; plugin 1041 (cannot be delegated) still applies to them.
          AND NOT (u.sam_account_name LIKE 'MSOL\\_%%'
                   OR u.sam_account_name LIKE 'AAD\\_%%'
                   OR COALESCE(u.description, '') ILIKE '%%Azure Active Directory Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Azure AD Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Entra Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Service account for the Synchronization Service%%')
          -- [v1.3] Fallback from retired plugin 1015: the collector's
          -- direct-memberOf flag also counts as membership, in case the
          -- Protected Users group's member edges were not collected.
          AND NOT COALESCE(u.protected_users_member, false)
          -- [v1.0] krbtgt (RID 502) is, by design, always disabled and
          -- structurally cannot be a normal Protected Users member --
          -- same exclusion precedent already established in plugin
          -- 1025 for the same account, applied here rather than
          -- treated as a fresh judgment call.
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-502'
    """,
}
