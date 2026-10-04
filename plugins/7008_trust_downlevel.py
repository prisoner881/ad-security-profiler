"""
Plugin 7008: Downlevel (NT4-Style) Trust

Reports trusts with trustType = 1 (TRUST_TYPE_DOWNLEVEL): a trust to a
Windows NT 4.0-style domain, or a trust created by NetBIOS name only. Such a
trust supports NTLM only -- no Kerberos, so no AES, no Kerberos armoring or
authentication policies across it -- and the partner is typically an
unsupported legacy domain or a Samba NT4-mode domain. It can also indicate a
modern trust created without DNS resolution, which breaks Kerberos
silently and leaves authentication on NTLM. PingCastle T-Downlevel flags it,
and trusts must be reviewed under the DISA AD STIG trust requirements.

One medium finding per trust. Disabled trusts (trust_direction 0) are
included -- the object still exists and can be re-enabled -- and flagged in
detail.
"""

PLUGIN = {
    "plugin_id": 7008,
    "category": "Trusts",
    "name": "Downlevel (NT4-Style) Trust",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "TRUST-7008",
    "framework_tags": [
        "NIST-800-53-AC-4", "NIST-800-53-AC-20", "NIST-800-53-SC-7",
        "NIST-800-53-CM-7", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.20", "ISO-27001-2022-A.8.22", "SOC2-CC6.6",
    ],
    "references": [
        {"title": "PingCastle health check rules (T-Downlevel)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Dirk-jan Mollema: Active Directory forest trusts part one - SID filtering",
         "url": "https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/"},
    ],
    "description": (
        "A trust has trustType 1 (downlevel / NT4-style). It authenticates "
        "with NTLM only -- no Kerberos, AES or authentication policies -- and "
        "usually points to an unsupported legacy domain or one created by "
        "NetBIOS name only."
    ),
    "remediation": (
        "Identify the partner (netdom trust <this domain> /domain:<partner> "
        "/verify). If it is a legacy NT4/Samba domain, migrate its "
        "resources and users and remove the trust (Active Directory Domains "
        "and Trusts -> Trusts -> Remove, on both sides). If the partner is a "
        "modern AD domain, delete the trust and recreate it using the "
        "partner's DNS name (with SID filtering / quarantine and selective "
        "authentication) after fixing DNS resolution (conditional "
        "forwarders) between the domains."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Downlevel (NT4-style, NTLM-only) trust with "'
                || COALESCE(t.trust_partner, '(unknown)') || '"'
                || CASE WHEN t.trust_direction = 0 THEN ' (disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_type', t.trust_type,
                'trust_direction', t.trust_direction,
                'trust_attributes', t.trust_attributes,
                'sid_filtering_enabled', t.sid_filtering_enabled
            ) AS detail
        FROM ad_trust t
        JOIN directory_object o
          ON o.object_guid = t.object_guid AND o.client_id = t.client_id AND NOT o.is_deleted
        WHERE t.client_id = %(client_id)s
          AND t.valid_to IS NULL
          AND t.trust_type = 1
    """,
}
