"""
Plugin 1012: Privileged Account Without Smartcard Required

Smartcard-required authentication is one of the few MFA-adjacent controls
directly visible in AD's own schema. This is a soft recommendation, not a
hard finding -- many organizations legitimately don't use smartcards at
all, in which case this fires for essentially every privileged account
and simply isn't actionable. Deliberately kept at low/info severity and
worded as a recommendation, not a violation.

[v1.5] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.6] Inclusion is now CURRENT privilege only (v_privileged_principal).
adminCount = 1 alone no longer qualifies: SDProp never clears it when an
account leaves a protected group, so former admins ("orphaned adminCount")
kept being reported as privileged. admin_count stays in detail. krbtgt
(RID 502; disabled, never logs on interactively) is excluded. detail gains
has_spn so service accounts, which usually cannot use smart cards and need
a different control (gMSA, authentication policy), are recognisable.

[v1.7] Entra Connect / Azure AD Connect sync accounts (MSOL_<hex> connector,
AAD_<hex> ADSync service account, or the installer's description) are no
longer reported: a service account cannot use a smart card, and their exposure
is reported by plugin 10009.
"""

PLUGIN = {
    "plugin_id": 1012,
    "category": "User Accounts",
    "name": "Privileged Account Without Smartcard Logon Required",
    "version": "1.7",
    "revision_date": "2026-10-07",
    "remediation": (
    'Enable smartcard-required authentication for the account, or if smartcards '
    "aren't practical in this environment, implement an equivalent "
    'phishing-resistant MFA mechanism for privileged access (Windows Hello for '
    'Business or FIDO2 security keys are the current standard alternatives).'
),
    "control_id": "PRIV-104",
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.1",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [],
    "description": (
        "Smartcard-required authentication is one of the few MFA-adjacent "
        "controls directly visible in AD's own schema (smartcard_required "
        "on the account). This is a soft recommendation, not a hard "
        "finding: many organizations legitimately don't use smartcards, "
        "in which case this will fire broadly and isn't independently "
        "actionable -- treat as informational context for accounts "
        "already known to be privileged, not as a standalone compliance "
        "failure. Privileged means currently privileged (protected-group "
        "membership, direct or nested, or Tier 0 control, per "
        "v_privileged_principal); a stale adminCount alone does not count. "
        "Equivalent controls (Windows Hello for Business, FIDO2, "
        "authentication policy silos) are not visible here."
    ),
    "base_severity": "low",
    "query": """
        WITH privileged_check AS (
            -- [v1.5] "Privileged" is the shared Tier 0 definition in
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
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN u.is_enabled THEN 'low' ELSE 'info' END AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' does not require smartcard logon'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources,
                'has_spn', COALESCE(cardinality(u.service_principal_names), 0) > 0
            ) AS detail
        FROM ad_user u
        -- [v1.6] current privilege only; orphaned adminCount=1 no longer
        -- qualifies on its own.
        JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND NOT u.smartcard_required
          -- [v1.7] Entra Connect / Azure AD Connect sync accounts (MSOL_ connector,
          -- AAD_ / ADSync service account, or the installer's description) are
          -- service accounts: they cannot use smart cards. Their exposure is plugin 10009's
          -- finding; plugin 1041 (cannot be delegated) still applies to them.
          AND NOT (u.sam_account_name LIKE 'MSOL\\_%%'
                   OR u.sam_account_name LIKE 'AAD\\_%%'
                   OR COALESCE(u.description, '') ILIKE '%%Azure Active Directory Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Azure AD Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Entra Connect%%'
                   OR COALESCE(u.description, '') ILIKE '%%Service account for the Synchronization Service%%')
          -- [v1.6] krbtgt (RID 502) is not an interactive account.
          AND NOT EXISTS (
                SELECT 1 FROM directory_object o
                WHERE o.object_guid = u.object_guid
                  AND o.client_id = u.client_id
                  AND o.object_sid LIKE '%%-502')
    """,
}
