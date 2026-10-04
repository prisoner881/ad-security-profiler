"""
Plugin 4026: Domain Is Supported by Only One Domain Controller

Directly cited against DISA Active Directory Domain STIG V-243500
(CAT II): "If there is only one domain controller in the OU, this is
a finding" -- conditioned in the STIG's own text on the domain's RMF
Availability categorization being moderate or high ("If the
Availability categorization of the domain is low, this is NA").
Confirmed against the current STIG text (V3R7) directly.

That RMF categorization is organizational context this project has no
visibility into -- nothing in AD records how a domain was formally
categorized for availability purposes. Rather than guess at it (or
silently skip this check entirely), this is reported as a WARN
regardless of category: a single domain controller is a genuine
resilience risk on its own technical merits -- no redundancy for
hardware failure, patching downtime, or a compromised/corrupted DC --
independent of whatever formal RMF paperwork applies. Framed
accordingly: PASS/FAIL here is about the count itself, and the
STIG's specific applicability condition (does moderate/high
Availability categorization apply here) is left for the reviewer to
resolve using the reported count as their evidence.

[v1.1] Counts writable DCs only. Since schema v36 is_domain_controller
also covers read-only DCs, which would have hidden a single writable DC
behind an RODC (an RODC is no substitute for a second writable DC).
Also no longer counts stale DC objects: a writable DC counts as active
when it is enabled and its lastLogonTimestamp is within 30 days of the
collection run (lastLogonTimestamp lags up to ~14 days). The finding is
raised when there is exactly one writable DC object, or when there are
several but only one is active (e.g. a decommissioned DC whose metadata
was never cleaned up). The detail lists the DCs.
"""

PLUGIN = {
    "plugin_id": 4026,
    "category": "Domain",
    "name": "Domain Is Supported by Only One Domain Controller",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Deploy at least one additional domain controller for this "
        "domain. A single domain controller is a single point of "
        "failure: hardware failure, a botched patch, or a compromised/"
        "corrupted DC leaves the domain with no functioning "
        "authentication or directory service until it's restored. If "
        "this domain's Risk Management Framework Availability "
        "categorization is formally documented as low, confirm that "
        "categorization is current and still accurate before treating "
        "this as acceptable risk."
    ),
    "control_id": "STIG-V-243500",
    "framework_tags": [
        "NIST-800-53-CP-10",
        "NIST-CSF-2.0-PR.DS-11",
        "ISO-27001-2022-A.8.13",
        "SOC2-A1.2",
        "DISA-STIG-V-243500",
    ],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243500",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243500"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243500 (CAT II): domains "
        "with a moderate or high Availability categorization must be "
        "supported by more than one domain controller. This project "
        "has no visibility into a domain's formal RMF categorization, "
        "so this is reported whenever only one writable DC exists (or "
        "only one is active -- enabled and logged on within 30 days; "
        "read-only DCs are not counted), regardless "
        "of category -- a single DC is a real resilience risk on its "
        "own merits, and the categorization question is left for the "
        "reviewer to resolve using this finding as evidence."
    ),
    "base_severity": "medium",
    "query": """
        WITH run AS (
            SELECT COALESCE(sr.completed_at, sr.started_at) AS run_ts
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s AND sr.run_id = %(run_id)s
        ),
        wdc AS (
            -- [v1.1] writable DCs only (RODCs excluded); active = enabled
            -- and lastLogonTimestamp within 30 days of the run.
            SELECT c.object_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, c.object_guid::text) AS name,
                   (c.is_enabled IS NOT FALSE
                    AND c.last_logon_timestamp IS NOT NULL
                    AND c.last_logon_timestamp >= (SELECT run_ts FROM run) - interval '30 days') AS is_active
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND c.is_domain_controller
              AND NOT c.is_read_only_dc
        ),
        dc_count AS (
            SELECT count(*) AS n,
                   count(*) FILTER (WHERE is_active) AS n_active,
                   COALESCE(jsonb_agg(jsonb_build_object('name', name, 'active', is_active)
                                      ORDER BY lower(name), name), '[]'::jsonb) AS dcs
            FROM wdc
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243500 (applicability depends on this '
                'domain''s documented RMF Availability categorization)' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' is supported by only one domain controller' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'domain_controller_count', dc.n,
                'active_domain_controller_count', dc.n_active,
                'writable_domain_controllers', dc.dcs
            ) AS detail
        FROM ad_domain d
        CROSS JOIN dc_count dc
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND (dc.n = 1 OR dc.n_active = 1)
    """,
}
