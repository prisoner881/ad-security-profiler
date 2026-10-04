"""
Plugin 4025: AD-Integrated DNS Zone Allows Nonsecure Dynamic Updates

Confirmed directly against Microsoft's own [MS-DNSP] specification
before building this (not inferred from a third party's tool):
DSPROPERTY_ZONE_ALLOW_UPDATE (property Id 0x2 within a zone's
dNSProperty attribute) is a 3-state value -- ZONE_UPDATE_OFF (0, no
dynamic updates at all), ZONE_UPDATE_UNSECURE (1, both secure and
nonsecure updates accepted), ZONE_UPDATE_SECURE (2, only
Kerberos/TSIG-authenticated updates accepted). The concerning state is
specifically UNSECURE: any client on the network, authenticated or
not, can create or overwrite records in the zone without proving who
they are. This is the underlying mechanism behind several well-known
attacks -- registering a rogue record to intercept traffic intended
for a real host (including spoofing WPAD for credential capture), or
overwriting an existing record's IP to redirect it. ZONE_UPDATE_OFF is
not flagged here alongside UNSECURE -- it's a different operational
tradeoff (dynamic updates disabled entirely, which breaks automatic
DC/client record registration) but is not itself a security weakness.

Requires adprofiler.py v0.5.6's targeted, per-zone raw_attributes read
of dNSProperty -- deliberately NOT read through the generic bulk
collection path (see adprofiler.py's dns_zone_typed_columns docstring
for why: that path's generic bytes-handling silently corrupts this
attribute's packed binary structure for the common case where its
values happen to decode as valid, if unprintable, UTF-8). Scoped to
domain-scoped AD-integrated zones only (DomainDnsZones partition) --
forest-scoped zones and non-AD-integrated (file-based) zones are not
covered; see adprofiler.py's own DNS_ZONE_ATTRS comment for why.

[v1.1] Requires adprofiler 0.5.15 (schema v36): parse_dns_zone_allow_update
previously required >= 4 data bytes, but DSPROPERTY_ZONE_ALLOW_UPDATE
carries a single byte (DNS_ZONE_UPDATE is an 8-bit enum), so
allow_update was NULL for every real zone and this plugin could never
fire. The collector now reads the 1-byte value. As a guard against a
silent repeat, the plugin also raises a low 'warn' on the domain when
DNS zones were collected but the dynamic-update setting could not be
determined for any of them (parser or collection failure), instead of
passing.
"""

PLUGIN = {
    "plugin_id": 4025,
    "category": "Domain",
    "name": "AD-Integrated DNS Zone Allows Nonsecure Dynamic Updates",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Change the zone's dynamic update setting to \"Secure only\": "
        "in the DNS Manager console, right-click the zone -> "
        "Properties -> General tab -> Dynamic updates -> select "
        "\"Secure only\" (requires the zone to be AD-integrated, which "
        "it already is). Equivalently via PowerShell: `Set-DnsServerPrimaryZone "
        "-Name <zone> -DynamicUpdate Secure`. Confirm no non-domain-"
        "joined systems currently depend on registering records in "
        "this zone via nonsecure updates before changing it, since "
        "those would need an alternative registration method "
        "afterward."
    ),
    "control_id": "DOM-425",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft [MS-DNSP]: DNS_ZONE_UPDATE enumeration",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e"},
        {"title": "Microsoft: Securing DNS zones -- Configure secure dynamic updates",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc755193(v=ws.10)"},
    ],
    "description": (
        "An AD-integrated DNS zone's dynamic update setting is "
        "\"Nonsecure and secure\" rather than \"Secure only\" -- any "
        "client on the network, authenticated or not, can create or "
        "overwrite DNS records in this zone without proving who they "
        "are. Underlies several well-known attacks, including "
        "registering a rogue record to intercept traffic meant for a "
        "real host (e.g. spoofing WPAD for credential capture) or "
        "overwriting an existing record to redirect it."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            z.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'DNS zone "' || z.zone_name || '" allows nonsecure dynamic updates '
                || '(any client can create or overwrite records without authentication)' AS summary,
            jsonb_build_object(
                'zone_name', z.zone_name,
                'allow_update', z.allow_update
            ) AS detail
        FROM ad_dns_zone z
        WHERE z.client_id = %(client_id)s
          AND z.valid_to IS NULL
          AND z.allow_update = 1

        UNION ALL

        -- [v1.1] Coverage guard: zones collected, but allow_update is
        -- NULL for every one of them -> the check could not run.
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, d.object_guid::text)
                || ': the dynamic update setting could not be determined for any '
                || 'collected AD-integrated DNS zone (verify "Secure only" manually)' AS summary,
            jsonb_build_object(
                'zones_collected', zc.n,
                'zones_with_allow_update', zc.n_known
            ) AS detail
        FROM ad_domain d
        CROSS JOIN (
            SELECT count(*) AS n,
                   count(z.allow_update) AS n_known
            FROM ad_dns_zone z
            WHERE z.client_id = %(client_id)s
              AND z.valid_to IS NULL
        ) zc
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND zc.n > 0
          AND zc.n_known = 0
    """,
}
