"""
Plugin 10110: Privileged Entra ID Account with a Weak On-Premises Posture

Cross-domain attack path (hybrid identity). Reports AD user accounts that
are synchronized to Entra ID (entra_user.on_prem_object_guid resolved to
the AD object) and whose Entra account holds a highly privileged directory
role -- active or PIM-eligible, directly or through a role-assignable group
-- while the AD account itself is any of:

  * Kerberoastable: a servicePrincipalName on the user account (plugin 1009);
  * AS-REP roastable: DONT_REQ_PREAUTH, UAC 0x400000 (plugin 1013);
  * PASSWD_NOTREQD, UAC 0x20 (plugin 1002);
  * password never expires (plugin 1001);
  * password last set more than 365 days ago (plugin 1036 uses 3 years for
    AD-privileged accounts; one year here, as the design asks);
  * trusted for unconstrained delegation (UAC 0x80000 or a delegation_edge
    'unconstrained' row) or for protocol transition
    (TRUSTED_TO_AUTH_FOR_DELEGATION, UAC 0x1000000).

Why: with password hash sync, pass-through authentication or federation,
the cloud administrator's password IS the AD password. Cracking a roasted
ticket offline, guessing a blank or ancient password, or abusing delegation
on-premises turns into a Global Administrator (or other Tier 0 role) sign-in
in the tenant. CISA SCuBA MS.AAD.7.3 requires privileged cloud users to be
cloud-only for exactly this reason. Chain plugin in the style of 1026-1030
(MITRE ATT&CK T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, T1078.004
Cloud Accounts).

Highly privileged roles (TIER0, by role template id): Global, Privileged
Role, Privileged Authentication, Security, Hybrid Identity, Application,
Cloud Application, Exchange, SharePoint, User, Conditional Access,
Authentication and Intune Administrator.

Data: entra_directory_role_member (Tier A, includes eligible rows and
members via groups) joined to entra_user for the AD object GUID
(falling back to the role-member row's own on_prem_object_guid), then the
current ad_user row (valid_to IS NULL) and delegation_edge. No AD run
dependency. Disabled AD accounts are excluded: a disabled AD account syncs
as a disabled cloud account and cannot sign in (plugin 10111 covers who
could re-enable or take it over). pwdLastSet = 0 (the FILETIME epoch) is
"must change at next logon", not an old password, and is not counted.

Severity: critical. One row per AD user (object_guid = the AD objectGUID),
listing every privileged role and every weakness, sorted.
"""

PLUGIN = {
    "plugin_id": 10110,
    "category": "Hybrid Identity",
    "name": "Privileged Entra ID Account with a Weak On-Premises Posture",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10110",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.3",
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-800-53-AC-6(2)",
        "NIST-800-53-IA-5", "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-05", "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-7.2.1", "PCI-DSS-4.0-7.2.2", "PCI-DSS-4.0-8.3.9", "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-5.4", "CIS-CSC-8-6.8", "CIS-CSC-8-5.2", "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.8.2", "ISO-27001-2022-A.5.17",
        "SOC2-CC6.3", "SOC2-CC6.1",
        "HIPAA-164.308(a)(4)(ii)(B)", "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1558.003", "MITRE-ATTCK-T1558.004", "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.3: cloud-only privileged accounts)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Protecting Microsoft 365 from on-premises attacks",
         "url": "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks"},
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
        {"title": "MITRE ATT&CK T1558.004: AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "Reports AD accounts synchronized to Entra ID whose cloud identity holds a highly "
        "privileged Entra role (active or eligible, direct or via a group) while the AD "
        "account is Kerberoastable, AS-REP roastable, PASSWD_NOTREQD, set to never expire, "
        "has a password older than a year, or is trusted for unconstrained or "
        "protocol-transition delegation. The cloud administrator signs in with the AD "
        "password, so an on-premises roast, crack or delegation abuse becomes a tenant "
        "administrator. Disabled AD accounts are not reported. One finding per AD account."
    ),
    "remediation": (
        "Give privileged Entra roles only to cloud-only accounts (SCuBA MS.AAD.7.3): create a "
        "dedicated cloud-only admin account (user@tenant.onmicrosoft.com), move the role "
        "assignment (or PIM eligibility) to it and remove it from the synced account. Until "
        "then, fix the AD weakness on the synced account: remove user SPNs "
        "(Set-ADUser <sam> -ServicePrincipalNames @{Remove='...'}), clear DONT_REQ_PREAUTH and "
        "PASSWD_NOTREQD (Set-ADAccountControl <sam> -DoesNotRequirePreAuth $false "
        "-PasswordNotRequired $false), clear 'password never expires', reset the password to a "
        "long random value, remove unconstrained / protocol-transition delegation "
        "(Set-ADAccountControl <sam> -TrustedForDelegation $false "
        "-TrustedToAuthForDelegation $false), and mark the account 'sensitive and cannot be "
        "delegated' or add it to Protected Users."
    ),
    "base_severity": "critical",
    "query": """
        WITH priv_role (template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        holder AS (
            SELECT COALESCE(eu.on_prem_object_guid, rm.on_prem_object_guid) AS ad_guid,
                   rm.member_id,
                   COALESCE(eu.user_principal_name, rm.member_upn) AS upn,
                   pr.role_name,
                   rm.assignment_type,
                   rm.via_group_id,
                   rm.via_group_display_name
            FROM entra_directory_role_member rm
            JOIN priv_role pr ON pr.template_id = rm.role_template_id
            LEFT JOIN entra_user eu
              ON eu.client_id = rm.client_id AND eu.entra_object_id = rm.member_id
            WHERE rm.client_id = %(client_id)s
              AND rm.member_type = '#microsoft.graph.user'
              AND COALESCE(eu.on_prem_object_guid, rm.on_prem_object_guid) IS NOT NULL
        ),
        holder_agg AS (
            SELECT h.ad_guid,
                   min(h.member_id::text) AS entra_object_id,
                   min(h.upn) AS upn,
                   string_agg(DISTINCT h.role_name, ', ' ORDER BY h.role_name) AS role_list,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'role', h.role_name,
                       'assignment_type', h.assignment_type,
                       'via_group', COALESCE(h.via_group_display_name, h.via_group_id::text)
                   )) AS role_assignments
            FROM holder h
            GROUP BY h.ad_guid
        ),
        weak AS (
            SELECT ha.*, u.object_guid, u.sam_account_name, u.user_principal_name AS ad_upn,
                   u.user_account_control, u.pwd_last_set, u.pwd_never_expires,
                   u.service_principal_names, u.admin_count,
                   array_remove(ARRAY[
                       CASE WHEN COALESCE(array_length(u.service_principal_names, 1), 0) > 0
                            THEN 'Kerberoastable (user SPN)' END,
                       CASE WHEN (COALESCE(u.user_account_control, 0) & 4194304) <> 0
                            THEN 'AS-REP roastable (no Kerberos pre-authentication)' END,
                       CASE WHEN (COALESCE(u.user_account_control, 0) & 32) <> 0
                            THEN 'password not required (PASSWD_NOTREQD)' END,
                       CASE WHEN u.pwd_never_expires
                              OR (COALESCE(u.user_account_control, 0) & 65536) <> 0
                            THEN 'password never expires' END,
                       CASE WHEN u.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
                             AND u.pwd_last_set < now() - interval '365 days'
                            THEN 'password older than one year' END,
                       CASE WHEN (COALESCE(u.user_account_control, 0) & 524288) <> 0
                              OR EXISTS (SELECT 1 FROM delegation_edge de
                                         WHERE de.client_id = u.client_id
                                           AND de.source_guid = u.object_guid
                                           AND de.valid_to IS NULL
                                           AND de.delegation_type = 'unconstrained')
                            THEN 'trusted for unconstrained delegation' END,
                       CASE WHEN (COALESCE(u.user_account_control, 0) & 16777216) <> 0
                            THEN 'trusted for protocol-transition delegation' END
                   ], NULL) AS weaknesses
            FROM holder_agg ha
            JOIN ad_user u
              ON u.client_id = %(client_id)s
             AND u.object_guid = ha.ad_guid
             AND u.valid_to IS NULL
            JOIN directory_object d
              ON d.client_id = u.client_id AND d.object_guid = u.object_guid
             AND NOT d.is_deleted
            WHERE u.is_enabled IS NOT FALSE
        )
        SELECT
            'fail' AS status,
            w.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Synced AD account "' || COALESCE(w.sam_account_name, w.ad_upn, w.object_guid::text)
                || '" holds privileged Entra role(s) ' || w.role_list
                || ' as "' || COALESCE(w.upn, w.entra_object_id) || '" but on-premises is '
                || array_to_string(w.weaknesses, ', ')
                || ' -- an on-premises compromise of this account is a cloud administrator compromise'
                AS summary,
            jsonb_build_object(
                'ad_sam_account_name', w.sam_account_name,
                'ad_user_principal_name', w.ad_upn,
                'entra_object_id', w.entra_object_id,
                'entra_user_principal_name', w.upn,
                'privileged_entra_roles', w.role_assignments,
                'weaknesses', to_jsonb(w.weaknesses),
                'service_principal_names', w.service_principal_names,
                'user_account_control', w.user_account_control,
                'pwd_last_set', w.pwd_last_set,
                'password_age_days', CASE WHEN w.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
                                          THEN EXTRACT(DAY FROM now() - w.pwd_last_set)::int END,
                'admin_count', w.admin_count,
                'related_plugins', jsonb_build_array(1001, 1002, 1009, 1010, 1013, 1036, 10018),
                'scuba_policy', 'MS.AAD.7.3'
            ) AS detail
        FROM weak w
        WHERE cardinality(w.weaknesses) > 0
    """,
}
