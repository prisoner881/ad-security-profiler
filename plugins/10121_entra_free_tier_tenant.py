"""
Plugin 10121: Free-Tier Entra ID Tenant (No P1/P2): 7-Day Log Retention

Reports a tenant with no enabled Microsoft Entra ID P1 or P2 service plan
(v_entra_tenant_capability.has_p1 false, from /subscribedSkus).

Why: without P1/P2 the tenant keeps sign-in and audit logs for only 7 days,
the sign-in log and the authentication-methods registration reports are not
available through the API, and Conditional Access, Identity Protection and
PIM cannot be used. Incident response on anything older than a week is
impossible unless logs are exported, and several other plugins (sign-in
activity, MFA registration, risk, PIM) show NOT ASSESSED for this reason.
Mainly informational: it explains coverage gaps and weak IR readiness.

Data: entra_tenant_license via v_entra_tenant_capability. Requires source
'subscribed_skus'; a finding is produced only when that read succeeded
(license_status = 'ok') -- an unknown licence state is not reported.
Severity: low. One row per tenant (object_guid = md5('10121:' || client_id)).
"""

PLUGIN = {
    "plugin_id": 10121,
    "category": "Hybrid Identity",
    "name": "Free-Tier Entra ID Tenant (No P1/P2): 7-Day Log Retention",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10121",
    "requires_sources": ["subscribed_skus"],
    "framework_tags": [
        "NIST-800-53-AU-2", "NIST-800-53-AU-12", "NIST-800-53-AU-3",
        "NIST-CSF-2.0-DE.CM-03",
        "PCI-DSS-4.0-10.2.1", "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.2", "CIS-CSC-8-8.5",
        "ISO-27001-2022-A.8.15",
        "SOC2-CC7.2",
        "HIPAA-164.312(b)",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra data retention",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention"},
        {"title": "Microsoft Entra ID licensing",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/licensing"},
        {"title": "Microsoft: Integrate Microsoft Entra logs with Azure Monitor logs",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-integrate-activity-logs-with-azure-monitor-logs"},
    ],
    "description": (
        "Reports a tenant without an enabled Microsoft Entra ID P1 or P2 licence. Such a tenant "
        "keeps sign-in and audit logs for only 7 days, has no sign-in log or MFA-registration "
        "reporting through the API, and cannot use Conditional Access, Identity Protection or "
        "PIM. Informational: it explains why several plugins are NOT ASSESSED and why "
        "investigation of older activity is impossible without a log export."
    ),
    "remediation": (
        "License Entra ID P1 (included in Microsoft 365 E3 / Business Premium) or P2 (E5) for "
        "the users, which extends log retention to 30 days and enables Conditional Access and "
        "sign-in reporting. Independently of licence, export the Entra audit log to a SIEM or "
        "Log Analytics workspace (Diagnostic settings, or a scheduled pull of "
        "/auditLogs/directoryAudits) so that it is retained per policy (e.g. 12 months, "
        "M-21-31 / PCI 10.5.1)."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10121:' || c.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'No Entra ID P1/P2: 7-day log retention, no sign-in/registration reporting, '
                || 'no Conditional Access' AS summary,
            jsonb_build_object(
                'has_p1', c.has_p1,
                'has_p2', c.has_p2,
                'has_workload_id', c.has_workload_id,
                'subscribed_skus', COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                                 'sku_part_number', l.sku_part_number,
                                                 'capability_status', l.capability_status)
                                                 ORDER BY l.sku_part_number, l.sku_id)
                                             FROM entra_tenant_license l
                                             WHERE l.client_id = c.client_id), '[]'::jsonb),
                'log_retention_days', 7
            ) AS detail
        FROM v_entra_tenant_capability c
        WHERE c.client_id = %(client_id)s
          AND c.license_status = 'ok'
          AND NOT c.has_p1
    """,
}
