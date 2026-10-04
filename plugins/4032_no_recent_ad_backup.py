"""
Plugin 4032: No Recent Active Directory Backup

Every backup taken through the Windows backup API (Windows Server Backup,
wbadmin, any VSS-aware AD backup product) updates the dSASignature attribute
on the head of each naming context it covers. The originating-change time of
dSASignature in the NC head's msDS-ReplAttributeMetaData is therefore the time
of the last backup of that partition, readable over LDAP by any user. The
collector stores it per naming context (domain, Configuration, Schema,
DomainDnsZones, ForestDnsZones) in ad_backup_status.

Why it matters: a working, recent system state backup is the only way back
from ransomware that encrypts or wipes domain controllers, a mass deletion
without the Recycle Bin, or a forest compromise that requires the Microsoft
forest recovery procedure. PingCastle A-BackupMetadata, the CISA/NSA/Five
Eyes "Detecting and Mitigating Active Directory Compromises" guidance (2024)
and NIST SP 800-53 CP-9 all require it. Backups older than the tombstone
lifetime (180 days by default) cannot be restored at all without
reintroducing lingering objects.

Logic: ONE finding for the domain (object_guid = domain root) when any
naming context is 'never_backed_up' or its last backup is more than 30 days
older than the collection time (high), or more than 7 days older (medium).
The summary lists the affected naming contexts per bucket, sorted; exact
timestamps and ages are in detail only. NCs whose metadata was 'unreadable'
are listed in detail only and do not raise a finding on their own. No rows in
ad_backup_status (pre-v38 collector) -> no finding.

Caveats: backups that do not go through the AD backup API (e.g. hypervisor
snapshots without VSS AD integration, or a backup of a DC in another
domain of the forest for the domain NC) do not update dSASignature, so they
are invisible here -- which is itself a warning sign, because such copies
are often not restorable as AD backups. Ages are measured against the time
the row was collected, not the time the plugin runs.
"""

PLUGIN = {
    "plugin_id": 4032,
    "category": "Domain",
    "name": "No Recent Active Directory Backup",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "OPS-4032",
    "framework_tags": [
        "NIST-800-53-CP-9", "NIST-800-53-CP-10", "NIST-CSF-2.0-PR.DS-11",
        "CIS-CSC-8-11.2", "CIS-CSC-8-11.3", "ISO-27001-2022-A.8.13",
        "SOC2-A1.2", "HIPAA-164.308(a)(7)(ii)(A)",
    ],
    "references": [
        {"title": "PingCastle health check rules (A-BackupMetadata)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "CISA et al.: Detecting and Mitigating Active Directory Compromises",
         "url": "https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises"},
    ],
    "description": (
        "One or more directory partitions (domain, Configuration, Schema, "
        "DNS application partitions) have never been backed up through the "
        "AD backup API, or their last backup (dSASignature originating-change "
        "time on the naming context head) is more than 7 days (medium) or 30 "
        "days (high) old. Without a recent system state backup, ransomware "
        "on the domain controllers or a forest compromise cannot be "
        "recovered from."
    ),
    "remediation": (
        "Back up the system state of at least two domain controllers per "
        "domain (including one that holds the forest-wide partitions) at "
        "least daily, e.g. wbadmin start systemstatebackup "
        "-backuptarget:<volume> -quiet, or an AD-aware backup product using "
        "the Windows backup API. Keep copies offline/immutable and separate "
        "from AD-joined infrastructure, test restores regularly (including a "
        "forest recovery exercise), and keep backups younger than the "
        "tombstone lifetime. Verify afterwards with repadmin /showbackup *."
    ),
    "base_severity": "high",
    "query": """
        WITH nc AS (
            SELECT b.naming_context, b.read_status, b.last_backup_at, b.collected_at,
                   CASE
                       WHEN b.read_status = 'never_backed_up' THEN 'never'
                       WHEN b.read_status = 'ok' AND b.last_backup_at IS NOT NULL
                            AND b.last_backup_at < b.collected_at - interval '30 days' THEN 'over30'
                       WHEN b.read_status = 'ok' AND b.last_backup_at IS NOT NULL
                            AND b.last_backup_at < b.collected_at - interval '7 days' THEN 'over7'
                       WHEN b.read_status = 'ok' AND b.last_backup_at IS NOT NULL THEN 'recent'
                       ELSE 'unreadable'
                   END AS bucket
            FROM ad_backup_status b
            WHERE b.client_id = %(client_id)s
        ),
        agg AS (
            SELECT
                string_agg(naming_context, ', ' ORDER BY naming_context)
                    FILTER (WHERE bucket = 'never') AS never_list,
                string_agg(naming_context, ', ' ORDER BY naming_context)
                    FILTER (WHERE bucket = 'over30') AS over30_list,
                string_agg(naming_context, ', ' ORDER BY naming_context)
                    FILTER (WHERE bucket = 'over7') AS over7_list,
                bool_or(bucket IN ('never', 'over30')) AS any_high,
                bool_or(bucket IN ('never', 'over30', 'over7')) AS any_fail,
                jsonb_agg(jsonb_build_object(
                    'naming_context', naming_context,
                    'read_status', read_status,
                    'last_backup_at', last_backup_at,
                    'collected_at', collected_at,
                    'days_since_backup', CASE WHEN last_backup_at IS NOT NULL
                        THEN floor(extract(epoch FROM (collected_at - last_backup_at)) / 86400)::int END,
                    'bucket', bucket
                ) ORDER BY naming_context) FILTER (WHERE bucket <> 'unreadable') AS naming_contexts,
                jsonb_agg(naming_context ORDER BY naming_context)
                    FILTER (WHERE bucket = 'unreadable') AS unreadable_naming_contexts
            FROM nc
        )
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.any_high THEN 'high' ELSE 'medium' END AS fd_severity,
            'No recent Active Directory backup for domain '
                || COALESCE(d.dns_root, o.dn_current) || ': '
                || array_to_string(ARRAY_REMOVE(ARRAY[
                       CASE WHEN a.never_list IS NOT NULL
                            THEN 'never backed up: ' || a.never_list END,
                       CASE WHEN a.over30_list IS NOT NULL
                            THEN 'no backup for over 30 days: ' || a.over30_list END,
                       CASE WHEN a.over7_list IS NOT NULL
                            THEN 'no backup for over 7 days: ' || a.over7_list END
                   ], NULL), '; ') AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'naming_contexts', COALESCE(a.naming_contexts, '[]'::jsonb),
                'unreadable_naming_contexts', COALESCE(a.unreadable_naming_contexts, '[]'::jsonb),
                'thresholds_days', jsonb_build_object('medium', 7, 'high', 30),
                'tombstone_lifetime_days', d.tombstone_lifetime_days
            ) AS detail
        FROM agg a
        CROSS JOIN ad_domain d
        JOIN directory_object o
          ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND a.any_fail
    """,
}
