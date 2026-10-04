"""
Plugin 4036: Tier 0 Accounts Not Protected by an Authentication Policy Silo

Authentication policy silos (Windows Server 2012 R2 DFL and later) restrict
where an account may obtain Kerberos tickets from -- e.g. Tier 0 admins only
from Tier 0 hosts/PAWs -- and can shorten their TGT lifetime. Together with
Protected Users they are Microsoft's mechanism for containing privileged
credentials: a Domain Admin's password or hash stolen on a workstation is
useless if the silo's policy only allows that account to authenticate from
domain controllers and PAWs. ANSSI's hardening levels (4+) and Microsoft's
privileged access guidance expect Tier 0 accounts in a silo.

Logic (one finding, object_guid = domain root):
  * ad_domain.authn_silos is an empty array -> low, "no authentication policy
    silos are defined";
  * otherwise, enabled Tier 0 user accounts (v_privileged_principal joined to
    ad_user; krbtgt, RID 502, excluded -- it cannot be siloed) whose
    msDS-AssignedAuthNPolicySilo (ad_user.assigned_authn_policy_silo) is
    NULL -> low; the summary gives the count, detail lists the accounts
    sorted.
authn_silos NULL (could not be read / pre-v38) -> no finding. Disabled
accounts are excluded (they cannot authenticate). Computer and gMSA accounts
are not considered here.

Caveats: assigned_authn_policy_silo is the computed backlink of a silo
assignment; a user that is listed as a silo member but not assigned (or vice
versa) is not protected, and a silo that is not enforced (audit only) does
not restrict anything -- detail lists every silo with its enforced flag.
Rows collected before schema v38 have NULL there too, so run a full rescan
after upgrading.
"""

PLUGIN = {
    "plugin_id": 4036,
    "category": "Domain",
    "name": "Tier 0 Accounts Not Protected by an Authentication Policy Silo",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-4036",
    "framework_tags": [
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.2", "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3", "HIPAA-164.308(a)(4)(ii)(B)", "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "Microsoft: Authentication policies and authentication policy silos",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos"},
        {"title": "Microsoft: Guidance about how to configure protected accounts",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to-configure-protected-accounts"},
        {"title": "MITRE ATT&CK T1078.002: Valid Accounts: Domain Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/002/"},
    ],
    "description": (
        "No authentication policy silo is defined, or enabled Tier 0 user "
        "accounts are not assigned to one. Without a silo, a privileged "
        "account can obtain Kerberos tickets from any machine, so credentials "
        "exposed on a workstation or server are directly usable for domain "
        "compromise."
    ),
    "remediation": (
        "Create an authentication policy that only allows Tier 0 accounts to "
        "authenticate from Tier 0 hosts (New-ADAuthenticationPolicy -Name "
        "'Tier0' -UserTGTLifetimeMins 240 -UserAllowedToAuthenticateFrom "
        "'<SDDL: member of the Tier 0 devices silo/claim>' -Enforce) and a "
        "silo using it (New-ADAuthenticationPolicySilo -Name 'Tier0' "
        "-UserAuthenticationPolicy 'Tier0' -ComputerAuthenticationPolicy "
        "'Tier0' -ServiceAuthenticationPolicy 'Tier0' -Enforce). Add the "
        "accounts, DCs and PAWs (Grant-ADAuthenticationPolicySiloAccess, "
        "then Set-ADAccountAuthenticationPolicySilo -Identity <account> "
        "-AuthenticationPolicySilo 'Tier0'). Enable KDC claims/compound "
        "authentication support by GPO first, start in audit mode (events "
        "in Microsoft-Windows-Authentication), then enforce. Keep a break-"
        "glass account outside the silo, documented and monitored."
    ),
    "base_severity": "low",
    "query": """
        WITH dom AS (
            SELECT d.object_guid, d.dns_root, d.authn_silos, d.authn_policy_count, o.dn_current
            FROM ad_domain d
            JOIN directory_object o
              ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
              AND d.authn_silos IS NOT NULL
              AND jsonb_typeof(d.authn_silos) = 'array'
        ),
        unsiloed AS (
            SELECT DISTINCT u.object_guid,
                   COALESCE(u.sam_account_name, o.sam_account_name, o.dn_current) AS account
            FROM v_privileged_principal pp
            JOIN ad_user u
              ON u.object_guid = pp.object_guid AND u.client_id = pp.client_id AND u.valid_to IS NULL
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id AND NOT o.is_deleted
            WHERE pp.client_id = %(client_id)s
              AND u.is_enabled IS TRUE
              AND COALESCE(o.object_sid, '') NOT LIKE 'S-1-5-21-%%-502'
              AND u.assigned_authn_policy_silo IS NULL
        ),
        un AS (
            SELECT count(*) AS n,
                   jsonb_agg(account ORDER BY account, object_guid) AS accounts
            FROM unsiloed
        )
        SELECT
            'fail' AS status,
            dm.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            CASE WHEN jsonb_array_length(dm.authn_silos) = 0 THEN
                     'No authentication policy silos are defined in the forest of domain '
                     || COALESCE(dm.dns_root, dm.dn_current)
                     || ': Tier 0 accounts can authenticate from any machine'
                 ELSE
                     un.n || ' enabled Tier 0 user account'
                     || CASE WHEN un.n = 1 THEN ' is' ELSE 's are' END
                     || ' not assigned to an authentication policy silo in domain '
                     || COALESCE(dm.dns_root, dm.dn_current)
            END AS summary,
            jsonb_build_object(
                'dns_root', dm.dns_root,
                'silo_count', jsonb_array_length(dm.authn_silos),
                'authn_policy_count', dm.authn_policy_count,
                'silos', (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                                     'name', s ->> 'name',
                                     'enforced', s -> 'enforced',
                                     'member_count', jsonb_array_length(COALESCE(s -> 'member_dns', '[]'::jsonb)))
                                 ORDER BY s ->> 'name'), '[]'::jsonb)
                          FROM jsonb_array_elements(dm.authn_silos) s),
                'unsiloed_tier0_accounts', COALESCE(un.accounts, '[]'::jsonb)
            ) AS detail
        FROM dom dm
        CROSS JOIN un
        WHERE jsonb_array_length(dm.authn_silos) = 0
           OR un.n > 0
    """,
}
