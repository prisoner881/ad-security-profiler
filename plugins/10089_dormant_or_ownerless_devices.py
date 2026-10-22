"""
Plugin 10089: Dormant Entra ID Devices

Reports enabled device objects in Entra ID that have not signed in for
more than 180 days (approximateLastSignInDateTime, or the registration
date when they never signed in), as one tenant-level finding with counts
by join type and the oldest 50 listed; and, separately, registered
(Workplace) devices with no registered owner.

Why: a stale device object keeps its device identity -- certificates and
Primary Refresh Token trust -- usable by whoever holds the old machine or
its disk, and a compliant or hybrid-joined state that Conditional Access
policies requiring a compliant or joined device accept. Stale objects also
hide real devices in compliance reporting. Microsoft recommends disabling,
then deleting, devices inactive beyond a set period. A registered device
with no owner cannot be traced to a person. CIS M365 and Monkey365 check
stale devices; Microsoft Zero Trust assessment.

Severity: low (warn), one row each: object_guid md5('10089:' || client_id
|| ':stale') and md5('10089:' || client_id || ':ownerless'). The summary
carries no counts, so the finding does not change with every collection;
counts and the oldest 50 devices are in detail. Data: entra_device (source devices, entra_graph_collector 0.9.0).
"""

PLUGIN = {
    "plugin_id": 10089,
    "category": "Hybrid Identity",
    "name": "Dormant Entra ID Devices",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10089",
    "requires_sources": ["devices"],
    "framework_tags": [
        "NIST-800-53-CM-8",
        "NIST-800-53-AC-2(3)",
        "NIST-CSF-2.0-ID.AM-01",
        "CIS-CSC-8-1.1",
        "ISO-27001-2022-A.5.9",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Manage stale devices in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/devices/manage-stale-devices"},
        {"title": "Microsoft Graph: device resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/device"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "Enabled Entra ID device objects have not signed in for over 180 days, or registered "
        "devices have no owner. Stale device identities keep their certificates, Primary "
        "Refresh Token trust and compliant / joined state usable, and blur device "
        "inventory."
    ),
    "remediation": (
        "Disable devices inactive for more than 180 days (Update-MgDevice -AccountEnabled "
        ":$false), wait a grace period, then delete them; for hybrid-joined devices clean "
        "up the on-premises computer object first so sync does not recreate them. Automate "
        "it (Microsoft's stale-device script or Intune device clean-up rules). Assign or "
        "remove registered devices without an owner."
    ),
    "base_severity": "low",
    "query": """
        WITH d AS (
            SELECT dv.*,
                   COALESCE(dv.approximate_last_sign_in_at, dv.registered_at) AS last_seen
              FROM entra_device dv
             WHERE dv.client_id = %(client_id)s
               AND dv.account_enabled IS NOT FALSE
        ),
        stale AS (
            SELECT * FROM d WHERE d.last_seen < d.collected_at - interval '180 days'
        ),
        ownerless AS (
            SELECT * FROM d WHERE d.trust_type = 'Workplace' AND d.registered_owner_count = 0
        )
        SELECT
            'warn' AS status,
            md5('10089:' || %(client_id)s::text || ':stale')::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Enabled Entra ID devices have not signed in for more than 180 days' AS summary,
            jsonb_build_object(
                'stale_device_count', count(*),
                'by_trust_type', (SELECT jsonb_object_agg(COALESCE(t, 'unknown'), n) FROM (
                        SELECT trust_type AS t, count(*) AS n FROM stale GROUP BY trust_type) x),
                'compliant_or_managed', count(*) FILTER (WHERE s.is_compliant OR s.is_managed),
                'oldest_50', to_jsonb((array_agg(jsonb_build_object(
                        'device', s.display_name, 'trust_type', s.trust_type,
                        'operating_system', s.operating_system, 'last_seen', s.last_seen)
                    ORDER BY s.last_seen, s.display_name))[1:50])
            ) AS detail
        FROM stale s
        HAVING count(*) > 0
        UNION ALL
        SELECT
            'warn',
            md5('10089:' || %(client_id)s::text || ':ownerless')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Registered (Workplace) devices have no registered owner',
            jsonb_build_object(
                'ownerless_device_count', count(*),
                'first_50', to_jsonb((array_agg(jsonb_build_object(
                        'device', o.display_name, 'operating_system', o.operating_system,
                        'registered_at', o.registered_at)
                    ORDER BY o.display_name, o.entra_object_id))[1:50]))
        FROM ownerless o
        HAVING count(*) > 0
    """,
}
