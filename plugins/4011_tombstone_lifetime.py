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

[v1.4] Two corrections. (1) The collected value is msDS-DeletedObjectLifetime
when set, otherwise tombstoneLifetime -- which is exactly the effective
deleted-object lifetime, since msDS-DeletedObjectLifetime defaults to
tombstoneLifetime. With the Recycle Bin enabled that is the window in
which a deleted object can be restored with all its attributes, not the
tombstone (recycled-object) lifetime, so the summary now says
"deleted-object lifetime". (2) The collector also falls back to the
assumed 60 days when the Directory Service object could not be read at
all, and this plugin cannot tell that apart from "neither attribute set"
(which modern forests never are: tombstoneLifetime is written at forest
creation since Server 2003 SP1). An assumed value is therefore reported
as unconfirmed at low severity instead of as a medium-severity short
lifetime.

[v1.5] The collector now records where the value came from
(ad_domain.tombstone_lifetime_source, schema v40), so the two cases
above are told apart:
  * 'msDS-DeletedObjectLifetime' / 'tombstoneLifetime' -- configured
    value; reported when below 90 days.
  * 'not_set' -- the Directory Service object was read and neither
    attribute is set, so the effective lifetime IS the MS-ADTS default of
    60 days (typical of forests created before Windows Server 2003 SP1).
    Reported as a real 60-day lifetime, no longer as "unconfirmed".
  * 'unreadable' -- the object could not be read; the lifetime is unknown
    (stored as NULL) and is reported as "could not be evaluated" at info
    severity rather than as a short lifetime.
Rows collected before schema v40 (source NULL) keep the v1.4 wording.
"""

PLUGIN = {
    "plugin_id": 4011,
    "category": "Domain",
    "name": "Tombstone Lifetime Unusually Short",
    "version": "1.5",
    "revision_date": "2026-10-05",
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
    "framework_tags": [
        "NIST-800-53-CP-9",
        "NIST-800-53-CP-10",
        "NIST-CSF-2.0-PR.DS-11",
        "CIS-CSC-8-11.2",
        "ISO-27001-2022-A.8.13",
        "SOC2-A1.2",
        "HIPAA-164.308(a)(7)(ii)(A)",
    ],
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
        "to be the common case, not an edge case. The value checked is "
        "msDS-DeletedObjectLifetime, or tombstoneLifetime when that is "
        "unset -- the effective deleted-object (recoverable) lifetime. "
        "When neither attribute is set, the effective lifetime is the "
        "MS-ADTS default of 60 days and is reported as such; when the "
        "Directory Service object could not be read, the lifetime is "
        "unknown and is reported as not evaluated (info)."
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
            CASE WHEN d.tombstone_lifetime_source = 'unreadable' THEN 'info' ELSE 'low' END
                AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || CASE
                     WHEN d.tombstone_lifetime_source = 'unreadable'
                       THEN ' deleted-object lifetime could not be read (the Directory Service '
                            || 'object was not readable by the collection account); not evaluated'
                     WHEN d.tombstone_lifetime_source = 'not_set'
                       THEN ' deleted-object lifetime is ' || d.tombstone_lifetime_days
                            || ' days (neither msDS-DeletedObjectLifetime nor tombstoneLifetime is '
                            || 'set, so the MS-ADTS default applies), below a conservative '
                            || '90-day threshold'
                     WHEN d.tombstone_lifetime_source IS NOT NULL
                       THEN ' deleted-object lifetime is ' || d.tombstone_lifetime_days
                            || ' days (' || d.tombstone_lifetime_source
                            || '), below a conservative 90-day threshold'
                     -- Collected before schema v40: the v1.4 wording.
                     WHEN d.tombstone_lifetime_is_default
                       THEN ' deleted-object lifetime could not be confirmed (neither '
                            || 'msDS-DeletedObjectLifetime nor tombstoneLifetime was found); '
                            || 'assumed ' || d.tombstone_lifetime_days
                            || ' days, below a conservative 90-day threshold (Assumed Value)'
                     ELSE ' deleted-object lifetime is ' || d.tombstone_lifetime_days
                          || ' days, below a conservative 90-day threshold (Confirmed Value)'
                   END AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'deleted_object_lifetime_days', d.tombstone_lifetime_days,
                'value_source', CASE d.tombstone_lifetime_source
                                     WHEN 'unreadable' THEN 'Directory Service object not readable'
                                     WHEN 'not_set' THEN 'MS-ADTS default (neither attribute set)'
                                     WHEN 'msDS-DeletedObjectLifetime' THEN 'msDS-DeletedObjectLifetime'
                                     WHEN 'tombstoneLifetime' THEN 'tombstoneLifetime (msDS-DeletedObjectLifetime unset)'
                                     ELSE CASE WHEN d.tombstone_lifetime_is_default
                                               THEN 'assumed MS-ADTS default (attributes unset or unreadable)'
                                               ELSE 'msDS-DeletedObjectLifetime, or tombstoneLifetime when unset'
                                          END
                                END,
                'tombstone_lifetime_source', d.tombstone_lifetime_source,
                'tombstone_lifetime_is_default', d.tombstone_lifetime_is_default
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND ( d.tombstone_lifetime_source = 'unreadable'
                OR (d.tombstone_lifetime_days IS NOT NULL AND d.tombstone_lifetime_days < 90) )
    """,
}
