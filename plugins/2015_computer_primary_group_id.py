"""
Plugin 2015: Computer Primary Group ID Set to a Privileged Group

Same technique as user-account plugin 1016, applied to computer objects.
The default for a computer object is 515 (Domain Computers); a
privileged-group RID here means membership that won't appear in that
group's own member list.

[v1.3] Added the computer-specific cases: primaryGroupID 516 (Domain
Controllers) on a computer that is not a writable DC -- the Domain
Controllers group holds DCSync rights on the domain root, so this is a
known DCSync persistence trick and is rated critical (it was only reported
by 2017, at low); 521 (Read-only Domain Controllers) and 498 (Enterprise
Read-only Domain Controllers) on a computer that is not a DC (high).
Removed 544: BUILTIN Administrators (S-1-5-32-544) is a domain-local group and can never
be a primary group (dead condition). Read-only DCs (whose default is 521)
are told apart by ad_computer.is_read_only_dc (schema v36). Plugin 2017
excludes exactly this set.
"""

PLUGIN = {
    "plugin_id": 2015,
    "category": "Computer Accounts",
    "name": "Computer Primary Group ID Set to a Privileged Group",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Investigate immediately -- this is a known attacker persistence "
        "technique, not a benign misconfiguration in most cases. "
        "Determine who or what set this value and when before simply "
        "correcting it. Once confirmed benign or after investigation "
        "concludes, reset primaryGroupID back to the standard default for "
        "a computer object (515, Domain Computers) via "
        "`Set-ADComputer -Replace @{primaryGroupID=515}`."
    ),
    "control_id": "PRIV-203",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1098",
    ],
    "references": [],
    "description": (
        "Same technique as user-account plugin 1016, applied to computer "
        "objects: group membership via primaryGroupID does not appear in "
        "the target group's own member list, so reviewing membership the "
        "normal way (via the group) would miss it entirely. The default "
        "for a computer object is 515 (Domain Computers), 516 (Domain "
        "Controllers) for a writable DC and 521 (Read-only Domain "
        "Controllers) for an RODC. Flags 512 Domain Admins, 518 Schema "
        "Admins, 519 Enterprise Admins and 520 Group Policy Creator Owners "
        "on any computer; 516 Domain Controllers on a computer that is not "
        "a writable DC (critical: the group holds DCSync rights, a known "
        "persistence trick); and 521 / 498 (Read-only / Enterprise "
        "Read-only Domain Controllers) on a computer that is not a DC. "
        "NOT downgraded when disabled -- this is persistent configuration "
        "that survives disablement."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'high' AS tool_severity,
            'PingCastle / ANSSI: "Accounts with modified PrimaryGroupID" '
                '(vuln3_primary_group_id_nochange) -- same rule already cited for '
                'the user-account equivalent, applies identically to computer objects' AS tool_reference,
            CASE WHEN c.is_domain_controller OR c.primary_group_id = 516
                 THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has primaryGroupID set to a privileged group (RID '
                || c.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'primary_group_id', c.primary_group_id,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller,
                'is_read_only_dc', c.is_read_only_dc
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          -- keep in sync with plugin 2017's exclusion
          AND (c.primary_group_id IN (512, 518, 519, 520)
               OR (c.primary_group_id = 516
                   AND (NOT c.is_domain_controller OR c.is_read_only_dc))
               OR (c.primary_group_id IN (498, 521) AND NOT c.is_domain_controller))
    """,
}
