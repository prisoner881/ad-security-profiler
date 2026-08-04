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
"""

PLUGIN = {
    "plugin_id": 2021,
    "category": "Computer Accounts",
    "name": "Domain Controller userAccountControl Value Is Inconsistent With DC Registration",
    "version": "1.2",
    "revision_date": "2026-07-15",
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
        "why it diverged."
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
        "directly from those hex constants, not approximated."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain Controller ' || c.sam_account_name || ' has userAccountControl='
                || c.user_account_control || ', matching neither the expected read/write DC '
                '(532480) nor RODC (83890176) value' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'user_account_control', c.user_account_control
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND c.user_account_control IS NOT NULL
          AND c.user_account_control NOT IN (532480, 83890176)
    """,
}
