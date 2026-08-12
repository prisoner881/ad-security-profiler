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
"""

PLUGIN = {
    "plugin_id": 4026,
    "category": "Domain",
    "name": "Domain Is Supported by Only One Domain Controller",
    "version": "1.0",
    "revision_date": "2026-08-12",
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
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243500",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243500"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243500 (CAT II): domains "
        "with a moderate or high Availability categorization must be "
        "supported by more than one domain controller. This project "
        "has no visibility into a domain's formal RMF categorization, "
        "so this is reported whenever only one DC exists, regardless "
        "of category -- a single DC is a real resilience risk on its "
        "own merits, and the categorization question is left for the "
        "reviewer to resolve using this finding as evidence."
    ),
    "base_severity": "medium",
    "query": """
        WITH dc_count AS (
            SELECT count(*) AS n
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
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
            jsonb_build_object('dns_root', d.dns_root, 'domain_controller_count', dc.n) AS detail
        FROM ad_domain d
        CROSS JOIN dc_count dc
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND dc.n = 1
    """,
}
