"""
Plugin 3020: Guest Account Is a Member of a Privileged Group

The built-in Guest account (RID 501) is designed to be the lowest-
trust identity in the domain -- disabled by default, and intended for
accounts with no password and no meaningful access. Membership in any
AdminSDHolder-protected privileged group is a severe contradiction of
that design intent: it would mean the domain's lowest-trust built-in
identity inherits Tier-0 access. This is checked regardless of
whether the account is currently enabled, since a disabled Guest
account with privileged group membership is still one re-enablement
away from being exploitable, and its presence in a privileged group
at all is itself the anomaly worth investigating.

[v1.3] Key Admins (526) and Enterprise Key Admins (527) added to the
privileged roots. Membership through primaryGroupID (e.g. Guest's
primaryGroupID set to 512, a known stealth-persistence trick) is now
caught: the collector records it as a group_member_edge (schema v36), so
it flows through v_effective_group_membership; detail carries
primary_group_id. Group names fall back to SID.
"""

PLUGIN = {
    "plugin_id": 3020,
    "category": "Groups",
    "name": "Guest Account Is a Member of a Privileged Group",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the Guest account from the privileged group(s) listed "
        "in this finding's evidence immediately -- there is no "
        "legitimate reason for the built-in Guest account to carry "
        "privileged group membership. Confirm the Guest account "
        "remains disabled (Microsoft's default) and investigate how "
        "this membership was added, since it is not a default AD "
        "configuration under any normal circumstance."
    ),
    "control_id": "PRIV-308",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-IA-2",
        "NIST-800-53-IA-4",
        "NIST-800-53-AC-2(9)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-8.2.1",
        "PCI-DSS-4.0-8.2.2",
        "PCI-DSS-4.0-2.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-4.7",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.5.16",
        "SOC2-CC6.3",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "HIPAA-164.312(a)(2)(i)",
        "MITRE-ATTCK-T1078.002",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "The built-in Guest account (RID 501) is designed to be the "
        "lowest-trust identity in the domain. Membership in any "
        "AdminSDHolder-protected privileged group severely contradicts "
        "that design intent. Checked regardless of whether the account "
        "is currently enabled, since a disabled Guest account with "
        "privileged group membership is still one re-enablement away "
        "from being exploitable. Covers nested membership and "
        "membership through primaryGroupID; privileged groups are the "
        "11 AdminSDHolder-protected groups plus Key Admins and "
        "Enterprise Key Admins, identified by RID."
    ),
    "base_severity": "critical",
    "query": """
        WITH well_known_roots AS (
            SELECT g.object_guid, COALESCE(g.sam_account_name, do2.object_sid) AS sam_account_name
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- Same verified 11-group AdminSDHolder-protected list used
              -- throughout this project (plugins 1025/3005/3008), plus
              -- [v1.3] Key Admins (526) / Enterprise Key Admins (527).
              AND do2.object_sid ~ '-(512|516|518|519|521|526|527|544|548|549|550|551|552)$'
        ),
        matches AS (
            SELECT gdo.object_guid, wkr.sam_account_name AS privileged_group_name, u.is_enabled,
                   u.primary_group_id
            FROM v_effective_group_membership vem
            JOIN well_known_roots wkr ON wkr.object_guid = vem.group_guid
            JOIN directory_object gdo ON gdo.object_guid = vem.member_guid AND gdo.client_id = vem.client_id
            JOIN ad_user u ON u.object_guid = gdo.object_guid AND u.client_id = gdo.client_id AND u.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND gdo.object_sid LIKE 'S-1-5-21-%%-501'
        ),
        -- [fix, applied proactively after the same architectural bug
        -- was found and fixed in plugins 9001/1037/3008/6006/6007/3021
        -- this session -- Guest nested in more than one privileged
        -- root group would collide on identity_guid the same way.]
        aggregated AS (
            SELECT object_guid, bool_or(is_enabled) AS is_enabled,
                   max(primary_group_id) AS primary_group_id,
                   array_agg(DISTINCT privileged_group_name ORDER BY privileged_group_name) AS privileged_group_names
            FROM matches
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Guest account (RID 501) is a member of privileged group(s): '
                || array_to_string(a.privileged_group_names, ', ') AS summary,
            jsonb_build_object(
                'privileged_groups', a.privileged_group_names,
                'guest_is_enabled', a.is_enabled,
                'primary_group_id', a.primary_group_id
            ) AS detail
        FROM aggregated a
    """,
}
