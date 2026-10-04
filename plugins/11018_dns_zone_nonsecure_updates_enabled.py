"""
Plugin 11018: DNS Zone Switched to Nonsecure Dynamic Updates

Change Detection companion to plugin 4025, which reports
AD-integrated zones allowing nonsecure dynamic updates. This one reports
the event: a zone whose dynamic-update setting (DSPROPERTY_ZONE_ALLOW_UPDATE
in dNSProperty, [MS-DNSP] 2.3.2.1.1) was "none" (0) or "secure only" (2)
at the previous successful collection run and is "nonsecure and secure"
(1) now.

Why: with nonsecure updates any host on the network -- authenticated or
not -- can register or overwrite records in the zone (for example a
WPAD, ISATAP or server record), redirecting clients to an attacker for
NTLM relay and credential capture (MITRE ATT&CK T1557 Adversary-in-the-
Middle, T1584.002 DNS Server). Switching a secure zone to nonsecure is
rarely legitimate and is a cheap, quiet preparation step.

Comparison: allow_update of the current ad_dns_zone version against the
version current at the previous succeeded sync_run (11002's lookup). Only
allow_update is compared, so the partition / wildcard / WPAD columns that
schema v38 adds to every zone are not changes, and a NULL previous value
(setting not found / not collected) is never treated as a change. The
collector versions a zone when allow_update changes. Zones first seen in
this window (including ForestDnsZones zones collected for the first time
by v38) are out of scope.

Severity: medium. One row per zone. Suppressed on a client's first
collection run.
"""

PLUGIN = {
    "plugin_id": 11018,
    "category": "Change Detection",
    "name": "DNS Zone Switched to Nonsecure Dynamic Updates",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11018",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-CM-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-8.11", "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32", "ISO-27001-2022-A.8.9",
        "SOC2-CC7.2", "SOC2-CC8.1", "SOC2-CC7.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1557", "MITRE-ATTCK-T1584.002",
    ],
    "references": [
        {"title": "Microsoft [MS-DNSP]: DNS_ZONE_UPDATE enumeration",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/d4b84209-f00c-478f-80d7-8dd0f1633d9e"},
        {"title": "MITRE ATT&CK T1557: Adversary-in-the-Middle",
         "url": "https://attack.mitre.org/techniques/T1557/"},
    ],
    "description": (
        "Reports AD-integrated DNS zones whose dynamic-update setting changed from "
        "'none' or 'secure only' at the previous successful collection run to "
        "'nonsecure and secure' now. Nonsecure updates let any host register or "
        "overwrite records in the zone (e.g. WPAD or server records) to redirect "
        "clients for credential capture and relay. A previously unknown setting "
        "(not collected) is never treated as a change, and the schema v38 zone "
        "columns are not compared. Suppressed on a client's first collection run."
    ),
    "remediation": (
        "Set the zone back to secure-only updates: Set-DnsServerPrimaryZone -Name "
        "<zone> -DynamicUpdate Secure (or DNS Manager > zone Properties > General > "
        "Dynamic updates: Secure only). Identify who changed it (DNS Server audit "
        "event 516/519 in Microsoft-Windows-DNSServer/Audit, or 5136 on the zone's "
        "dnsZone object) and review records created or modified since the change "
        "(Get-DnsServerResourceRecord -ZoneName <zone>, looking for wpad, isatap and "
        "records pointing to unexpected hosts)."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        cur AS (
            SELECT z.*, do2.dn_current, cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_dns_zone z
            CROSS JOIN prior_run pr
            JOIN directory_object do2
              ON do2.object_guid = z.object_guid AND do2.client_id = z.client_id
             AND NOT do2.is_deleted
            JOIN directory_object_version cv
              ON cv.version_id = z.version_id AND cv.object_guid = z.object_guid
             AND cv.client_id = z.client_id AND cv.valid_from = z.valid_from
            WHERE z.client_id = %(client_id)s
              AND z.valid_to IS NULL
              AND z.allow_update = 1
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'DNS zone "' || c.zone_name || '"'
                || CASE WHEN c.partition IS NOT NULL THEN ' (' || c.partition || ')' ELSE '' END
                || ' was switched from '
                || CASE prev.allow_update WHEN 0 THEN 'no dynamic updates'
                                          ELSE 'secure-only dynamic updates' END
                || ' to nonsecure and secure dynamic updates since the previous collection run'
                AS summary,
            jsonb_build_object(
                'zone_name', c.zone_name,
                'partition', c.partition,
                'distinguished_name', c.dn_current,
                'allow_update', c.allow_update,
                'previous_allow_update', prev.allow_update,
                'has_wpad_record', c.has_wpad_record,
                'has_wildcard_record', c.has_wildcard_record,
                'change_observed_run_id', c.change_run_id,
                'baseline_run_id', c.prev_run_id,
                'change_observed_at', c.valid_from,
                'corroborating_event_id', 5136
            ) AS detail
        FROM cur c
        JOIN LATERAL (
            SELECT p.allow_update
            FROM ad_dns_zone p
            JOIN directory_object_version pv
              ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
             AND pv.client_id = p.client_id AND pv.valid_from = p.valid_from
            WHERE p.object_guid = c.object_guid
              AND p.client_id = %(client_id)s
              AND p.valid_from < c.valid_from
              AND pv.run_id_valid_from <= c.prev_run_id
              AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
            ORDER BY p.valid_from DESC
            LIMIT 1
        ) prev ON TRUE
        WHERE prev.allow_update IN (0, 2)
    """,
}
