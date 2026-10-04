"""
Plugin 2021: Domain Controller userAccountControl Value Is Inconsistent With DC Registration

Directly cited from PingCastle's S-DCRegistration rule. A properly-
registered read/write DC has userAccountControl exactly equal to
SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION (0x00082000 = 532480); a
properly-registered RODC has it exactly equal to
PARTIAL_SECRETS_ACCOUNT | TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION |
WORKSTATION_TRUST_ACCOUNT (0x05001000 = 83890176). A DC computer object
that doesn't match either exact value is a genuine anomaly -- per
PingCastle's own text, this can result from manual or software
misconfiguration, or be a sign of compromise (e.g. rogue/DCShadow-style
DC registration).

[v1.3] RODCs are now actually covered (the 83890176 branch was dead
code while is_domain_controller only reflected SERVER_TRUST_ACCOUNT),
and each account is compared against the value expected for ITS role
instead of against either value: an account is treated as a DC when it
carries SERVER_TRUST_ACCOUNT (0x2000) or PARTIAL_SECRETS_ACCOUNT
(0x04000000), or has primaryGroupID 516 (Domain Controllers) / 521
(Read-only Domain Controllers); its role is RODC when it carries
0x04000000, or 521 without 0x2000. A read/write DC must have UAC 532480
and primaryGroupID 516; an RODC 83890176 and 521. This also catches an
ordinary computer whose primaryGroupID was set to 516 (which silently
makes it a member of Domain Controllers, i.e. grants it DCSync) and a
writable DC carrying the RODC value. The summary now names the expected
value for the account's role and any primaryGroupID mismatch.
"""

PLUGIN = {
    "plugin_id": 2021,
    "category": "Computer Accounts",
    "name": "Domain Controller userAccountControl Value Is Inconsistent With DC Registration",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm this userAccountControl value directly against the "
        "expected constants for the DC's actual role (532480 for a "
        "read/write DC, 83890176 for an RODC) -- if it doesn't match "
        "either, this is either a misconfiguration or worth treating as "
        "a potential compromise indicator (e.g. a DCShadow-style rogue "
        "DC registration) rather than assumed benign. Cross-check the "
        "Configuration partition's DC registration for this object "
        "(NTDS Settings presence, replication status) rather than "
        "correcting the attribute value alone without understanding "
        "why it diverged. A computer that is not a DC but has "
        "primaryGroupID 516 or 521 should be reset to 515 (Domain "
        "Computers) and investigated as a possible persistence mechanism."
    ),
    "control_id": "ANOM-104",
    "framework_tags": [],
    "references": [],
    "description": (
        "Directly cited from PingCastle's S-DCRegistration rule, which "
        "specifies the exact expected userAccountControl values: "
        "\"The user account control value for Read/Write DC is: "
        "SERVER_TRUST_ACCOUNT (0x00002000) | TRUSTED_FOR_DELEGATION "
        "(0x00080000) = 0x00082000. The user account control value for "
        "Read Only DC is: PARTIAL_SECRETS_ACCOUNT (0x04000000) | "
        "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION (0x01000000) | "
        "WORKSTATION_TRUST_ACCOUNT (0x00001000) = 0x05001000.\" "
        "PingCastle's own guidance on a mismatch: \"This rule result is "
        "either the result of a manual or software based "
        "misconfiguration. It can also be the sign of a compromise.\" "
        "Decimal values (532480 and 83890176 respectively) computed "
        "directly from those hex constants, not approximated. Each "
        "account is compared against the value for its own role (RODC "
        "when PARTIAL_SECRETS_ACCOUNT is set or primaryGroupID is 521), "
        "and the primaryGroupID is checked too (516 for a read/write DC, "
        "521 for an RODC): a non-DC computer with primaryGroupID 516 is "
        "a member of Domain Controllers and thereby holds DCSync rights."
    ),
    "base_severity": "high",
    "query": """
        WITH dc AS (
            SELECT c.*,
                   ((c.user_account_control & 67108864) <> 0
                    OR ((c.user_account_control & 8192) = 0 AND c.primary_group_id = 521)) AS rodc_role
            FROM ad_computer c
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND c.user_account_control IS NOT NULL
              AND (c.is_domain_controller
                   OR (c.user_account_control & (8192 | 67108864)) <> 0
                   OR c.primary_group_id IN (516, 521))
        ), chk AS (
            SELECT dc.*,
                   CASE WHEN rodc_role THEN 83890176 ELSE 532480 END AS expected_uac,
                   CASE WHEN rodc_role THEN 521 ELSE 516 END AS expected_pgid,
                   CASE WHEN rodc_role THEN 'Read-only Domain Controller ' ELSE 'Domain Controller ' END AS role_label
            FROM dc
        )
        SELECT
            'fail' AS status,
            object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            role_label || COALESCE(sam_account_name, object_guid::text)
                || CASE WHEN user_account_control <> expected_uac
                        THEN ' has userAccountControl=' || user_account_control
                             || ', not the expected '
                             || CASE WHEN rodc_role THEN 'RODC' ELSE 'read/write DC' END
                             || ' value (' || expected_uac || ')'
                        ELSE ' has the expected userAccountControl (' || expected_uac || ')' END
                || CASE WHEN primary_group_id IS DISTINCT FROM expected_pgid
                        THEN ' and primaryGroupID=' || COALESCE(primary_group_id::text, 'unset')
                             || ' (expected ' || expected_pgid || ')'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', sam_account_name,
                'user_account_control', user_account_control,
                'expected_user_account_control', expected_uac,
                'primary_group_id', primary_group_id,
                'expected_primary_group_id', expected_pgid,
                'role', CASE WHEN rodc_role THEN 'rodc' ELSE 'rwdc' END
            ) AS detail
        FROM chk
        WHERE user_account_control <> expected_uac
           OR primary_group_id IS DISTINCT FROM expected_pgid
        ORDER BY object_guid
    """,
}
