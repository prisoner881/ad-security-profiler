"""
Plugin 10028: Over-Trusted Named Locations

Reports each Conditional Access named location that is trusted too broadly:
- a trusted IP location (is_trusted) containing an IPv4 range wider than /16
  (more than 65,536 addresses) or an IPv6 range wider than /32;
- a location (trusted IP, untrusted IP or country) that an enabled policy
  requiring MFA excludes (conditions.locations.excludeLocations contains
  the location id, or 'AllTrusted' for a trusted location) -- i.e. sign-ins
  from there skip MFA.

Why it matters: "skip MFA from the office" turns any foothold inside the
trusted network -- a compromised workstation, a VPN account, a guest Wi-Fi
segment inside the range, or a shared cloud egress range -- into an MFA
bypass for every account, and password spraying from inside it succeeds
with the password alone (MITRE T1110.003). Trusted locations also lower
Identity Protection sign-in risk. Very wide trusted ranges (whole /8s,
cloud provider ranges) make the bypass reachable from far more of the
internet than intended. Microsoft recommends not exempting locations from
MFA and keeping trusted ranges to the organisation's own egress IPs.

Severity:
- fail / high: a trusted location with an over-wide range that is also
  excluded from an MFA policy;
- warn / medium: either condition alone.
One row per location, object_guid = the named location id. detail lists
the wide ranges and the MFA policies (enabled, 'mfa' built-in control or an
authentication strength) that exclude it.

Data caveats: needs the named locations (source named_locations,
Policy.Read.All) and, for the exclusion part, the CA policy conditions
(entra_graph_collector 0.7.0+; policies without conditions are ignored).
A range string without a prefix length is treated as a single address.
The legacy per-user MFA "trusted IPs" service setting is not collected.
"""

PLUGIN = {
    "plugin_id": 10028,
    "category": "Hybrid Identity",
    "name": "Over-Trusted Named Locations",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10028",
    "requires_sources": ["named_locations"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-SC-7",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.4",
        "ISO-27001-2022-A.8.5",
        "ISO-27001-2022-A.8.20",
        "SOC2-CC6.1",
        "SOC2-CC6.6",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "Microsoft: Using the location condition in a Conditional Access policy",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network"},
        {"title": "Microsoft: Block access by location / named locations",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location"},
        {"title": "MITRE ATT&CK T1110.003: Password Spraying",
         "url": "https://attack.mitre.org/techniques/T1110/003/"},
    ],
    "description": (
        "Named locations trusted too broadly: trusted IP locations with an "
        "IPv4 range wider than /16 or IPv6 wider than /32, and locations "
        "excluded from an enabled MFA Conditional Access policy so that "
        "sign-ins from there skip MFA. High when a wide trusted range is "
        "also exempt from MFA, otherwise medium."
    ),
    "remediation": (
        "Entra admin center -> Protection -> Conditional Access -> Named "
        "locations: limit trusted IP locations to the organisation's own "
        "egress addresses (exact /32s or small prefixes), never whole "
        "provider or cloud ranges; un-mark 'Trusted location' where it is "
        "not needed. Remove the location (or 'All trusted locations') from "
        "the exclusions of MFA policies -- with modern MFA methods and "
        "sign-in frequency there is little friction from requiring MFA on "
        "the corporate network too. If an exemption must stay, pair it with "
        "a compliant-device requirement rather than a password alone."
    ),
    "base_severity": "medium",
    "query": """
        WITH loc AS (
            SELECT nl.location_id, nl.display_name, nl.location_type, nl.is_trusted, nl.ip_ranges, nl.countries
              FROM entra_named_location nl
             WHERE nl.client_id = %(client_id)s
        ),
        wide AS (
            SELECT l.location_id,
                   jsonb_agg(r ORDER BY r) AS wide_ranges
              FROM loc l
              CROSS JOIN LATERAL unnest(l.ip_ranges) r
             WHERE l.location_type = 'ip'
               AND l.is_trusted IS TRUE
               AND substring(r FROM '/([0-9]{1,3})\\s*$') IS NOT NULL
               AND CASE WHEN position(':' IN r) > 0
                        THEN substring(r FROM '/([0-9]{1,3})\\s*$')::int < 32
                        ELSE substring(r FROM '/([0-9]{1,3})\\s*$')::int < 16 END
             GROUP BY l.location_id
        ),
        mfa_pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   CASE WHEN jsonb_typeof(p->'conditions'->'locations'->'excludeLocations') = 'array'
                        THEN p->'conditions'->'locations'->'excludeLocations' ELSE '[]'::jsonb END AS ex_locs
              FROM entra_security_posture sp
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(sp.ca_policies) = 'array' THEN sp.ca_policies ELSE '[]'::jsonb END) p
             WHERE sp.client_id = %(client_id)s
               AND p->>'state' = 'enabled'
               AND jsonb_typeof(p->'conditions') = 'object'
               AND (COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) ? 'mfa'
                    OR jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object')
        ),
        mfa_excl AS (
            SELECT l.location_id,
                   jsonb_agg(jsonb_build_object('policy', m.name, 'id', m.id,
                                                'via', CASE WHEN EXISTS (SELECT 1 FROM jsonb_array_elements_text(m.ex_locs) e
                                                                          WHERE lower(e) = l.location_id::text)
                                                            THEN 'location' ELSE 'AllTrusted' END)
                             ORDER BY m.name, m.id) AS excluding_policies
              FROM loc l
              JOIN mfa_pol m
                ON EXISTS (SELECT 1 FROM jsonb_array_elements_text(m.ex_locs) e
                            WHERE lower(e) = l.location_id::text)
                OR (l.is_trusted IS TRUE AND m.ex_locs ? 'AllTrusted')
             GROUP BY l.location_id
        )
        SELECT
            CASE WHEN w.location_id IS NOT NULL AND x.location_id IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            l.location_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN w.location_id IS NOT NULL AND x.location_id IS NOT NULL THEN 'high' ELSE 'medium' END
                AS fd_severity,
            'Named location "' || COALESCE(l.display_name, l.location_id::text) || '" '
                || CASE WHEN w.location_id IS NOT NULL AND x.location_id IS NOT NULL
                        THEN 'is trusted with an over-wide IP range and is exempt from MFA'
                        WHEN w.location_id IS NOT NULL
                        THEN 'is trusted with an over-wide IP range'
                        ELSE 'is exempt from an MFA Conditional Access policy' END AS summary,
            jsonb_build_object(
                'location_name', l.display_name,
                'location_type', l.location_type,
                'is_trusted', l.is_trusted,
                'wide_trusted_ranges', w.wide_ranges,
                'mfa_policies_excluding_location', x.excluding_policies,
                'countries', CASE WHEN l.location_type = 'country' THEN to_jsonb(l.countries) END
            ) AS detail
        FROM loc l
        LEFT JOIN wide w ON w.location_id = l.location_id
        LEFT JOIN mfa_excl x ON x.location_id = l.location_id
        WHERE w.location_id IS NOT NULL OR x.location_id IS NOT NULL
    """,
}
