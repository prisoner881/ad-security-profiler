"""
Plugin 2004: Local Administrator Password Not Centrally Managed (LAPS)

Neither legacy nor modern Windows LAPS is managing this machine's local
administrator password -- an unmanaged local admin password is a
standard lateral-movement vector when reused across machines, which is
extremely common without LAPS enforcing per-machine randomization.
Domain controllers are excluded; LAPS manages workstation/member-server
local admin accounts, not DC administrative accounts.
"""

PLUGIN = {
    "plugin_id": 2004,
    "category": "Computer Accounts",
    "name": "Local Administrator Password Not Managed by LAPS",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Deploy Windows LAPS (built into Windows since the April 2023 "
        "updates) or legacy Microsoft LAPS to this machine if not already "
        "installed, and confirm the corresponding GPO is actually linked "
        "and applying to the OU this computer resides in -- a common "
        "failure mode is LAPS being schema-extended and configured "
        "domain-wide but the GPO not actually reaching every OU. Absence "
        "here does not necessarily mean LAPS was never deployed at all; "
        "verify against the domain-wide LAPS schema detection this "
        "collector already reports before assuming a full rollout gap "
        "versus a per-machine GPO scoping gap."
    ),
    "control_id": "CRED-101",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Windows LAPS overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"},
        {"title": "DISA Active Directory Domain STIG V-243471: Local administrator accounts on domain systems must not share the same password",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243471"},
    ],
    "description": (
        "Neither ms-Mcs-AdmPwdExpirationTime (legacy LAPS) nor "
        "msLAPS-PasswordExpirationTime (modern Windows LAPS) is set on "
        "this computer, meaning its local administrator password is not "
        "being centrally rotated. An unmanaged local admin password is a "
        "standard lateral-movement vector, particularly when the same "
        "password is reused across many machines (a very common "
        "real-world pattern in environments that never deployed LAPS) -- "
        "compromising one machine's local admin credential then grants "
        "the same access to every other machine sharing it. Domain "
        "controllers are excluded from this check; LAPS manages "
        "workstation and member-server local admin accounts specifically, "
        "not DC administrative accounts. "
        "NOT downgraded when disabled, for the same reason as plugin "
        "2003: disabling the AD computer object does not disable the "
        "underlying machine's local administrator account, which remains "
        "unmanaged regardless of the AD object's state."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243471' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' has no local administrator password management (LAPS) configured' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND NOT c.is_domain_controller
          AND c.laps_expiration_legacy IS NULL
          AND c.laps_expiration_modern IS NULL
    """,
}
