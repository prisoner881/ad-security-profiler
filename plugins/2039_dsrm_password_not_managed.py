"""
Plugin 2039: DSRM Password Not Managed on Domain Controllers

Detects enabled writable domain controllers whose
msLAPS-PasswordExpirationTime (ad_computer.laps_expiration_modern) is
NULL, i.e. Windows LAPS is not backing up and rotating the Directory
Services Restore Mode (DSRM) administrator password.

Why it matters: every DC has a local DSRM administrator account whose
password is set at promotion and, without automation, is rarely changed
and often the same on every DC. With DsrmAdminLogonBehavior set to 2 (or
1 while AD DS is stopped) the DSRM account can log on over the network;
its hash, dumped from one DC's SAM, is a well-known domain persistence
technique (MITRE T1003.002 / DSRM backdoor). Windows LAPS (April 2023
updates onwards) can back up and rotate the DSRM password in AD
(msLAPS-EncryptedDSRMPassword) when its policy enables DSRM backup on
DCs; the expiration timestamp it writes on the DC's computer object is
what this check reads. Plugin 2004 checks LAPS on member computers and
excludes DCs, so DSRM rotation is otherwise unchecked. The DISA AD STIG
requires the DSRM password to be changed regularly.

Disabled DC computer accounts are skipped (not a functioning DC).
detail.windows_laps_schema_present tells whether the Windows LAPS
schema is in the forest (from ad_domain.laps_attribute_guids, which
lists msLAPS-PasswordExpirationTime when present; NULL = not collected,
pre-v38); without it the attribute cannot exist and the fix starts with
Update-LapsADSchema. detail.laps_schema_present is the older,
legacy-or-Windows-LAPS flag. Read-only DCs are excluded:
Microsoft documents Windows LAPS DSRM backup for writable DCs only
(verify against the current Windows LAPS documentation), so a finding on
an RODC could not be remediated with LAPS; rotate an RODC's DSRM password by other
means (`ntdsutil "set dsrm password"`).

One row per DC. medium.
"""

PLUGIN = {
    "plugin_id": 2039,
    "category": "Computer Accounts",
    "name": "DSRM Password Not Managed on Domain Controllers",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-2039",
    "framework_tags": [
        "MITRE-ATTCK-T1003.002", "DISA-STIG",
        "NIST-800-53-IA-5", "NIST-800-53-IA-5(1)", "NIST-CSF-2.0-PR.AA-01", "PCI-DSS-4.0-8.3.9",
        "CIS-CSC-8-5.2", "ISO-27001-2022-A.5.17", "SOC2-CC6.1",
        "NIST-800-53-CP-10", "CIS-CSC-8-11.2", "ISO-27001-2022-A.8.13",
    ],
    "references": [
        {"title": "Microsoft: Windows LAPS overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"},
        {"title": "MITRE ATT&CK T1003.002: OS Credential Dumping: Security Account Manager",
         "url": "https://attack.mitre.org/techniques/T1003/002/"},
    ],
    "description": (
        "Flags writable domain controllers that carry no "
        "msLAPS-PasswordExpirationTime, meaning Windows LAPS is not backing up and "
        "rotating their Directory Services Restore Mode administrator password. An "
        "unrotated, often shared DSRM password is a well-known domain persistence "
        "and lateral-movement path."
    ),
    "remediation": (
        "Enable Windows LAPS DSRM backup for domain controllers: extend the schema "
        "if needed (`Update-LapsADSchema`), grant DCs permission "
        "(`Set-LapsADComputerSelfPermission` on OU=Domain Controllers), and in a GPO "
        "linked to the Domain Controllers OU set 'Configure password backup "
        "directory' = Active Directory and 'Enable password encryption' = Enabled "
        "(DSRM backup requires encryption, domain functional level 2016+). Confirm "
        "with `Get-LapsADPassword -Identity <DC> -AsPlainText` from an authorized "
        "account. Until then, set a unique DSRM password per DC with "
        "`ntdsutil \"set dsrm password\"` and keep DsrmAdminLogonBehavior at 0."
    ),
    "base_severity": "medium",
    "query": """
        WITH dom AS (
            SELECT bool_or(d.laps_schema_present) AS laps_schema_present,
                   bool_or(CASE WHEN jsonb_typeof(d.laps_attribute_guids) = 'object'
                                THEN d.laps_attribute_guids ? 'msLAPS-PasswordExpirationTime' END)
                       AS windows_laps_schema_present
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            CASE WHEN c.is_read_only_dc THEN 'Read-only domain controller ' ELSE 'Domain controller ' END
                || COALESCE(c.sam_account_name, c.object_guid::text)
                || ': DSRM password is not backed up or rotated by Windows LAPS'
                || CASE WHEN dom.windows_laps_schema_present IS FALSE
                        THEN ' (Windows LAPS schema not present)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'is_read_only_dc', c.is_read_only_dc,
                'operating_system', c.operating_system,
                'windows_laps_schema_present', dom.windows_laps_schema_present,
                'laps_schema_present', dom.laps_schema_present
            ) AS detail
        FROM ad_computer c
        JOIN directory_object d
          ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
        LEFT JOIN dom ON true
        WHERE c.client_id = %(client_id)s
          AND c.valid_to IS NULL
          AND c.is_domain_controller
          AND NOT c.is_read_only_dc
          AND c.is_enabled IS NOT FALSE
          AND c.laps_expiration_modern IS NULL
        ORDER BY c.object_guid
    """,
}
