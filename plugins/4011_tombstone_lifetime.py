"""
Plugin 4011: Tombstone Lifetime Unusually Short

Tombstone lifetime governs how long a deleted object remains recoverable
and visible (including to this project's own deletion-detection logic --
see the extensive work on collect_deleted_objects() and
repair_orphaned_deleted_typed_rows() earlier in this project) before
being permanently purged. A short lifetime narrows the forensic and
recovery window after an incident, and -- directly relevant to this
project specifically -- narrows the window during which a deletion can
still be caught by a delta collection run that happens to be running
infrequently.

[v1.1] Now surfaces whether the underlying value is CONFIRMED (read
directly from an explicitly-configured attribute) or ASSUMED (neither
msDS-DeletedObjectLifetime nor its tombstoneLifetime fallback was set in
AD, so the collector used the MS-ADTS-specified last-resort default) --
a real trust distinction, not just an implementation detail. A "clean"
result riding on a confirmed value means something different than one
riding on an assumed one.
"""

PLUGIN = {
    "plugin_id": 4011,
    "category": "Domain",
    "name": "Tombstone Lifetime Unusually Short",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Confirm this is an intentional choice, not an artifact of an "
        "old default that was never revisited -- Windows Server 2003 SP1 "
        "and earlier defaulted to 60 days, which is commonly left "
        "unchanged through forest upgrades even after Microsoft raised "
        "the modern default to 180 days. If unintentional, raise "
        "msDS-DeletedObjectLifetime to at least the modern 180-day "
        "default via ADSI Edit or "
        "`Set-ADObject <forest-DN> -Replace @{msDS-DeletedObjectLifetime=180}`. "
        "A shorter value narrows both the forensic/recovery window after "
        "an incident and, in this project's own collection specifically, "
        "the window during which an infrequently-run delta collection "
        "can still catch a deletion before its tombstone is purged. If "
        "this finding shows the value as ASSUMED rather than CONFIRMED, "
        "prioritize explicitly setting msDS-DeletedObjectLifetime (or at "
        "minimum tombstoneLifetime) over the specific day-count concern "
        "-- an unconfirmed value is itself worth resolving regardless of "
        "what it turns out to be."
    ),
    "control_id": "POLICY-011",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: The AD Recycle Bin -- Understanding, Implementing, Best Practices, and Troubleshooting",
         "url": "https://techcommunity.microsoft.com/blog/askds/the-ad-recycle-bin-understanding-implementing-best-practices-and-troubleshooting/396944"},
    ],
    "description": (
        "Tombstone lifetime governs how long a deleted object remains "
        "recoverable and visible before being permanently purged. A "
        "short lifetime narrows the forensic and recovery window "
        "following an incident. Directly relevant to this project's own "
        "collection specifically: this project's deletion-detection "
        "logic (collect_deleted_objects(), and the self-healing "
        "reconciliation pass built to catch objects that slip through "
        "it) depends on tombstones remaining visible long enough for a "
        "collection run to observe them -- a short lifetime combined "
        "with an infrequent collection cadence increases the chance a "
        "deletion is missed entirely rather than correctly detected and "
        "reconciled. 90 days is used here as a conservative threshold "
        "(half the modern 180-day default), not a cited external "
        "standard. Surfaces whether the underlying value is CONFIRMED "
        "(read from an explicitly-configured attribute) or ASSUMED "
        "(neither msDS-DeletedObjectLifetime nor its tombstoneLifetime "
        "fallback was set, so the MS-ADTS-specified last-resort default "
        "of 60 days was used) -- a real trust distinction found "
        "necessary after a real collection run against real data showed "
        "the underlying attribute genuinely unreadable, which turned out "
        "to be the common case, not an edge case."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN d.tombstone_lifetime_is_default THEN 'medium' ELSE 'low' END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' tombstone lifetime is ' || d.tombstone_lifetime_days
                || ' days, below a conservative 90-day threshold'
                || CASE WHEN d.tombstone_lifetime_is_default
                        THEN ' (Assumed Value)'
                        ELSE ' (Confirmed Value)'
                   END AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'tombstone_lifetime_days', d.tombstone_lifetime_days,
                'tombstone_lifetime_is_default', d.tombstone_lifetime_is_default
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.tombstone_lifetime_days IS NOT NULL
          AND d.tombstone_lifetime_days < 90
    """,
}
