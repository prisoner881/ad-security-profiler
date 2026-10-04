"""
Plugin 4030: UPN, SPN or SPN Alias Uniqueness Verification Disabled

Character 21 of the forest-wide dSHeuristics attribute, on
CN=Directory Service,CN=Windows NT,CN=Services,<Configuration NC>, is a
three-bit mask that switches off the principal-name uniqueness checks added
by CVE-2021-42282 (KB5008382):

    bit 0 (value 1)  UPN uniqueness verification disabled
    bit 1 (value 2)  SPN uniqueness verification disabled
    bit 2 (value 4)  SPN alias uniqueness verification disabled

0 means all three are enforced, which is the default and the desired state.

Why this matters more in 2026 than it did in 2021: these checks are precisely
the guardrails that the two current name-confusion vulnerabilities had to
defeat. KerberLoss (CVE-2026-25177) and ResetNightmare (CVE-2026-27912) both
work by smuggling invisible Unicode characters past the uniqueness comparison
so that two values differ to the directory while appearing identical to an
administrator. **Where these checks are switched off, none of that is
necessary.** Duplicate SPNs, shadowing SPN aliases and conflicting UPNs can be
created directly, in plain ASCII, on a domain controller that is fully patched
against both CVEs. The patches do not restore a check that an administrator
has deliberately turned off.

This is also a setting that tends to be switched off once and left. The usual
reason is an ADMT intra-forest migration or an authoritative restore failing
with ERROR_DS_SPN_VALUE_NOT_UNIQUE_IN_FOREST (0x21C7) or
ERROR_DS_UPN_VALUE_NOT_UNIQUE_IN_FOREST (8648); Microsoft's own KB articles
suggest relaxing dSHeuristics as a workaround. The migration finishes, nobody
reverts the change, and the forest runs without the check for years.

Reported at critical because it is a forest-wide removal of a security control
rather than a single misconfigured object, and because it silently amplifies
plugins 4028 and 4029: if either of those reports findings while this one
does too, the duplicates did not require an exploit to create.

Requires schema v33 (adds ad_domain.dsheuristics_uniqueness) and a collection
run on adprofiler.py v0.5.11 or later. Domains where the value is NULL are
deliberately not reported -- NULL means the Directory Service object could not
be read, which is not the same as the checks being enforced, and reporting it
either way would be wrong.

[v1.1] Summary wording: v1.0 always said "partially disabled", even
when every check was off (value 7). The summary now says "fully
disabled" for 7 and "disabled" otherwise, followed by the list of
disabled checks.
"""

PLUGIN = {
    "plugin_id": 4030,
    "category": "Domain",
    "name": "UPN, SPN or SPN Alias Uniqueness Verification Disabled",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Re-enable the checks by setting character 21 of dSHeuristics back to "
        "0, or by clearing the attribute entirely if nothing else in it is "
        "needed. Read the current value first: "
        "(Get-ADObject 'CN=Directory Service,CN=Windows NT,CN=Services,"
        "CN=Configuration,DC=<domain>,DC=<tld>' -Properties dSHeuristics)"
        ".dSHeuristics -- then write it back with only character 21 changed, "
        "using Set-ADObject -Replace @{dSHeuristics='<new value>'}. Do not "
        "shorten the string: earlier characters control unrelated behaviour, "
        "including anonymous LDAP access at character 7 (see plugin 4015), "
        "and truncating it will change settings you did not intend to touch. "
        "Before re-enabling, find the duplicates that already exist, because "
        "the check is not retroactive -- turning it back on prevents new "
        "conflicts but leaves existing ones in place. Plugins 4028 and 4029 "
        "enumerate duplicate SPNs and shadowed HOST aliases; plugin 1043 "
        "finds UPNs copied from another account's sAMAccountName. Resolve "
        "those first, or re-enabling the check will simply make the next "
        "legitimate change fail while the dangerous existing entries persist. "
        "If the setting was introduced for an ADMT migration or an "
        "authoritative restore that has since completed, there is no reason "
        "to keep it and it should be reverted now. If a migration is still in "
        "progress, treat the relaxation as a temporary change with an owner "
        "and an end date, and compensate in the meantime by monitoring "
        "Security event 5136 for servicePrincipalName and userPrincipalName "
        "modifications. Note that Domain Admins bypass these checks "
        "regardless, so administrative tooling that genuinely needs to create "
        "a conflicting value can do so without disabling the check "
        "forest-wide."
    ),
    "control_id": "DOM-426",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-2",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-4.1",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.9",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1484",
        "MITRE-ATTCK-T1558",
        "CVE-2021-42282",
        "CVE-2026-25177",
        "CVE-2026-27912",
    ],
    "references": [
        {"title": "Microsoft KB5008382: Verification of uniqueness for UPN, SPN and SPN alias (CVE-2021-42282)",
         "url": "https://support.microsoft.com/en-us/topic/kb5008382-verification-of-uniqueness-for-user-principal-name-service-principal-name-and-the-service-principal-name-alias-cve-2021-42282-4651b175-290c-4e59-8fcb-e4e5cd0cdb29"},
        {"title": "MS-ADTS 6.1.1.2.4.1.2: dSHeuristics",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/10e15bbc-0f19-4e3f-abfd-0e97b0e85b46"},
        {"title": "Semperis: KerberLoss and ResetNightmare",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
    ],
    "description": (
        "Reports that the forest-wide UPN, SPN or SPN alias uniqueness "
        "verifications have been disabled through character 21 of "
        "dSHeuristics. These checks, introduced by CVE-2021-42282, prevent "
        "the creation of duplicate or conflicting principal names. They are "
        "the control that both 2026 name-confusion vulnerabilities -- "
        "KerberLoss and ResetNightmare -- had to bypass using invisible "
        "Unicode characters; with the checks switched off, the same "
        "conflicting names can be created directly on a fully patched domain "
        "controller. The setting is most often a leftover from an ADMT "
        "migration or an authoritative restore. Domains where the value could "
        "not be determined are not reported."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                -- Losing UPN uniqueness is the sharper edge: it is the direct
                -- precondition for ResetNightmare-style impersonation.
                WHEN (d.dsheuristics_uniqueness & 1) = 1 THEN 'critical'
                WHEN (d.dsheuristics_uniqueness & 2) = 2 THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, do2.dn_current)
                || ' has forest-wide principal-name uniqueness verification '
                -- [v1.1] not always "partially"
                || CASE WHEN d.dsheuristics_uniqueness = 7 THEN 'fully disabled'
                        ELSE 'disabled' END
                || ' via dSHeuristics character 21 (value '
                || d.dsheuristics_uniqueness || '): '
                || array_to_string(ARRAY_REMOVE(ARRAY[
                       CASE WHEN (d.dsheuristics_uniqueness & 1) = 1
                            THEN 'UPN uniqueness' END,
                       CASE WHEN (d.dsheuristics_uniqueness & 2) = 2
                            THEN 'SPN uniqueness' END,
                       CASE WHEN (d.dsheuristics_uniqueness & 4) = 4
                            THEN 'SPN alias uniqueness' END
                   ], NULL), ', ')
                || ' disabled -- conflicting principal names can be created '
                   'directly, without the Unicode bypass that CVE-2026-25177 '
                   'and CVE-2026-27912 require' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'distinguished_name', do2.dn_current,
                'dsheuristics_uniqueness_value', d.dsheuristics_uniqueness,
                'upn_uniqueness_disabled', (d.dsheuristics_uniqueness & 1) = 1,
                'spn_uniqueness_disabled', (d.dsheuristics_uniqueness & 2) = 2,
                'spn_alias_uniqueness_disabled', (d.dsheuristics_uniqueness & 4) = 4,
                'expected_value', 0,
                'directory_service_object',
                    'CN=Directory Service,CN=Windows NT,CN=Services,<Configuration NC>',
                'related_plugins', jsonb_build_array(1043, 4028, 4029),
                'note',
                    'Re-enabling is not retroactive; resolve existing '
                    'duplicates first (plugins 1043, 4028, 4029)'
            ) AS detail
        FROM ad_domain d
        JOIN directory_object do2
            ON do2.object_guid = d.object_guid AND do2.client_id = d.client_id
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          -- NULL means undetermined, not enforced. Do not report it.
          AND d.dsheuristics_uniqueness IS NOT NULL
          AND d.dsheuristics_uniqueness > 0
    """,
}
