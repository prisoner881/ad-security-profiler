"""
Plugin 4015: Anonymous LDAP Operations Enabled Forest-Wide

dSHeuristics 7th character = "2" enables anonymous (unauthenticated)
LDAP operations against every DC in the forest. Confirmed directly
against Microsoft's own protocol specification (MS-ADTS) and a current
DISA STIG (V-243503). Distinct from and more consequential than plugin
3012 (Pre-Windows 2000 group membership): that finding requires the
group's own read permissions to already be broadly granted, whereas this
setting governs whether anonymous LDAP binds are permitted at the
protocol level at all, forest-wide, independent of any specific group's
ACLs.
"""

PLUGIN = {
    "plugin_id": 4015,
    "category": "Domain",
    "name": "Anonymous LDAP Operations Enabled Forest-Wide",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Set the 7th character of dSHeuristics back to \"0\" (or remove "
        "the attribute entirely, which defaults to the same safe "
        "state) on CN=Directory Service,CN=Windows NT,CN=Services,"
        "CN=Configuration,<forest-root-DN> via ADSI Edit or "
        "Set-ADObject, preserving every other character in the string "
        "unchanged -- per Microsoft's own guidance, do not modify any "
        "character other than the 7th when making this change."
    ),
    "control_id": "ANOM-103",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA STIG V-243503: Anonymous Access to AD forest data above the rootDSE level must be disabled",
         "url": "https://www.stigviewer.com/stigs/active_directory_forest/2025-05-15/finding/V-243503"},
    ],
    "description": (
        "Directly cited against DISA STIG V-243503 and confirmed "
        "against Microsoft's own protocol specification (MS-ADTS): "
        "dSHeuristics' 7th character, when set to \"2\", enables "
        "anonymous LDAP operations against every domain controller in "
        "the forest. Per Microsoft's own documentation, once enabled, "
        "\"anonymous clients can perform any operation that is "
        "permitted by the access control list (ACL)\" -- meaning the "
        "practical impact scales with whatever ACLs already grant "
        "broad read access (see plugin 3012). Distinct from that "
        "finding: this setting governs whether anonymous LDAP binds "
        "are permitted at the protocol level at all, forest-wide, "
        "independent of any specific group's membership. Default "
        "(attribute unset) is safe; this has been the safe default "
        "since Windows Server 2003."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_I' AS stig_severity,
            'DISA STIG V-243503: anonymous access to AD forest data above the '
                'rootDSE must not be permitted (dSHeuristics 7th character)' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' permits anonymous LDAP operations forest-wide (dSHeuristics 7th '
                'character = "2")' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'dsheuristics_anonymous_access', d.dsheuristics_anonymous_access) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.dsheuristics_anonymous_access
    """,
}
