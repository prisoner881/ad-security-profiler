"""
Plugin 2004: Local Administrator Password Not Centrally Managed (LAPS)

Neither legacy nor modern Windows LAPS is managing this machine's local
administrator password -- an unmanaged local admin password is a
standard lateral-movement vector when reused across machines, which is
extremely common without LAPS enforcing per-machine randomization.
Domain controllers are excluded; LAPS manages workstation/member-server
local admin accounts, not DC administrative accounts.

[v1.3] Scope narrowed to objects that actually have a local SAM: group and
standalone managed service accounts (collected as computers -- they are
subclasses of computer -- and identified by msDS-GroupMSAMembership or by
living under CN=Managed Service Accounts) are excluded, and only computers
reporting a Windows operatingSystem are checked (Linux/Samba/macOS/NAS
joins, cluster name objects and the AZUREADSSOACC account carry none).
Read-only DCs are excluded through is_domain_controller, which covers them
since schema v36. New: a machine whose LAPS expiration time is more than 60
days in the past (the LAPS client stopped rotating) is reported at low.
"""

PLUGIN = {
    "plugin_id": 2004,
    "category": "Computer Accounts",
    "name": "Local Administrator Password Not Managed by LAPS",
    "version": "1.3",
    "revision_date": "2026-10-04",
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
        "versus a per-machine GPO scoping gap. Devices that back up their "
        "Windows LAPS password only to Microsoft Entra ID show no AD "
        "expiration time and are reported here; confirm in Entra before "
        "acting. For a stale LAPS expiration (LAPS was managing the "
        "machine but has stopped rotating), check that the machine is "
        "online, that the LAPS GPO/CSP still applies, and the "
        "LAPS event log (Applications and Services > Microsoft > Windows "
        "> LAPS) for errors; retire the account if the machine is gone."
    ),
    "control_id": "CRED-101",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-IA-2",
        "NIST-800-53-IA-4",
        "NIST-800-53-AC-2(9)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.1",
        "PCI-DSS-4.0-8.2.2",
        "PCI-DSS-4.0-2.2.2",
        "CIS-CSC-8-5.2",
        "CIS-CSC-8-4.7",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.5.16",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "HIPAA-164.312(a)(2)(i)",
        "DISA-STIG",
        "DISA-STIG-V-243471",
        "MITRE-ATTCK-T1078.003",
    ],
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
        WITH scope AS (
            SELECT c.*,
                   GREATEST(c.laps_expiration_legacy, c.laps_expiration_modern) AS laps_expiration
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND NOT c.is_domain_controller
              AND c.operating_system ILIKE 'Windows%%'
              AND o.dn_current NOT ILIKE '%%,CN=Managed Service Accounts,%%'
              AND NOT EXISTS (
                  SELECT 1 FROM directory_object_version dov
                  WHERE dov.object_guid = c.object_guid
                    AND dov.client_id = c.client_id
                    AND dov.valid_to IS NULL
                    AND dov.attributes_full->>'msDS-GroupMSAMembership' IS NOT NULL)
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243471' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.laps_expiration IS NULL THEN 'medium' ELSE 'low' END AS fd_severity,
            'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || CASE
                     WHEN c.laps_expiration IS NULL
                     THEN ' has no local administrator password management (LAPS) configured'
                     ELSE ' has a stale LAPS password (expired '
                          || to_char(c.laps_expiration AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                          || ', not rotated since)'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'laps_expiration_legacy', c.laps_expiration_legacy,
                'laps_expiration_modern', c.laps_expiration_modern
            ) AS detail
        FROM scope c
        WHERE c.laps_expiration IS NULL
           OR c.laps_expiration < now() - interval '60 days'
    """,
}
