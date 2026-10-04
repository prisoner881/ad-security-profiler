"""
Plugin 4031: Active Directory Recycle Bin Not Enabled

Reports a domain whose forest does not have the Active Directory Recycle Bin
optional feature enabled (msDS-EnabledFeature on CN=Partitions,<Configuration
NC> does not reference CN=Recycle Bin Feature).

Why it matters: without the Recycle Bin, a deleted object is reduced to a
tombstone that keeps only a handful of attributes -- group memberships,
most user attributes and every link are stripped. Recovering an accidentally
or maliciously deleted user, group, OU or GPO container then needs an
authoritative restore from a system state backup (a DC taken offline into
DSRM), and objects changed since the backup are lost. With the feature on,
deleted objects keep all attributes and links for the deleted-object lifetime
and can be restored online with Restore-ADObject. The CISA/NSA/Five Eyes
guidance "Detecting and Mitigating Active Directory Compromises" (2024) and
PingCastle (P-RecycleBin) list it as a recovery prerequisite; it maps to
NIST SP 800-53 CP-9/CP-10.

Data: ad_domain.recycle_bin_enabled (schema v38, collector 0.6.0). FALSE =
the Partitions object was read and the feature is not listed. NULL = it
could not be read (or the row predates v38) and is NOT reported -- unknown is
not the same as disabled. The feature is forest-wide; each collected domain
of the forest reports it.
"""

PLUGIN = {
    "plugin_id": 4031,
    "category": "Domain",
    "name": "Active Directory Recycle Bin Not Enabled",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "DOM-4031",
    "framework_tags": [
        "NIST-800-53-CP-9", "NIST-800-53-CP-10", "NIST-CSF-2.0-PR.DS-11",
        "CIS-CSC-8-11.2", "ISO-27001-2022-A.8.13", "SOC2-A1.2",
        "HIPAA-164.308(a)(7)(ii)(A)", "NIST-800-53-CM-6",
    ],
    "references": [
        {"title": "Microsoft AskDS: The AD Recycle Bin -- understanding, implementing, best practices and troubleshooting",
         "url": "https://techcommunity.microsoft.com/blog/askds/the-ad-recycle-bin-understanding-implementing-best-practices-and-troubleshooting/396944"},
        {"title": "CISA et al.: Detecting and Mitigating Active Directory Compromises",
         "url": "https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises"},
        {"title": "PingCastle health check rules (P-RecycleBin)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The Active Directory Recycle Bin optional feature is not enabled in "
        "the forest. Deleted objects are then stripped to tombstones (group "
        "memberships, links and most attributes are lost), and recovering an "
        "accidentally or maliciously deleted object requires an authoritative "
        "restore from backup. Domains where the setting could not be read "
        "are not reported."
    ),
    "remediation": (
        "Requires forest functional level Windows Server 2008 R2 or higher, "
        "and cannot be turned off again once enabled. As an Enterprise Admin: "
        "Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope "
        "ForestOrConfigurationSet -Target '<forest root DNS name>' (or Active "
        "Directory Administrative Center -> domain -> Enable Recycle Bin). "
        "Objects deleted before the feature was enabled stay tombstones. "
        "Check the deleted-object lifetime (msDS-DeletedObjectLifetime, "
        "defaulting to the tombstone lifetime) is long enough for your "
        "recovery window, and keep system state backups: the Recycle Bin "
        "does not replace them."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Active Directory Recycle Bin is not enabled for domain '
                || COALESCE(d.dns_root, o.dn_current, d.object_guid::text)
                || ': deleted objects can only be recovered by an authoritative restore'
                AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'distinguished_name', o.dn_current,
                'forest_root_dn', d.forest_root_dn,
                'domain_functional_level', d.functional_level,
                'recycle_bin_enabled', d.recycle_bin_enabled,
                'tombstone_lifetime_days', d.tombstone_lifetime_days
            ) AS detail
        FROM ad_domain d
        JOIN directory_object o
          ON o.object_guid = d.object_guid AND o.client_id = d.client_id
         AND NOT o.is_deleted
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          -- NULL = could not be read: not reported
          AND d.recycle_bin_enabled IS FALSE
    """,
}
