"""
Plugin 10039: Users Cannot Report Suspicious MFA Prompts

Reports the authentication methods policy setting "Report suspicious
activity" (reportSuspiciousActivitySettings) not turned on for all users.

Why: when it is on, a user who receives an MFA prompt (Authenticator push
or phone call) they did not start can report it; Entra ID then sets the
user's risk to high, which risk-based Conditional Access and ID
Protection act on, and the report is visible to administrators. Without
it, an MFA-fatigue attempt (MITRE T1621) leaves no user-raised signal.
'default' means disabled (Microsoft Graph documentation). EIDSCA AG02 /
AG03 and Microsoft's Zero Trust assessment (21841) check it.

Reported: state 'default' or 'disabled' (not enabled), or enabled for a
group rather than all users. The setting is only returned by the beta
authentication methods policy (entra_graph_collector 0.9.0 reads it from
beta; content.graph_version 'beta'); a policy read from v1.0, or one
without the setting, is not evaluated. warn / low, one tenant-level row
(object_guid md5('10039:' || client_id)).
"""

PLUGIN = {
    "plugin_id": 10039,
    "category": "Hybrid Identity",
    "name": "Users Cannot Report Suspicious MFA Prompts",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10039",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-AU-6",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1621",
    ],
    "references": [
        {"title": "Microsoft: Configure Microsoft Entra multifactor authentication settings (report suspicious activity)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#report-suspicious-activity"},
        {"title": "Microsoft Graph (beta): reportSuspiciousActivitySettings resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/reportsuspiciousactivitysettings?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1621: Multi-Factor Authentication Request Generation",
         "url": "https://attack.mitre.org/techniques/T1621/"},
    ],
    "description": (
        "'Report suspicious activity' is not turned on for all users, so a user who gets an "
        "MFA prompt they did not start cannot report it. Reporting raises the user's risk "
        "to high, which risk-based Conditional Access and ID Protection act on."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Settings > Report "
        "suspicious activity: State = Enabled, Target = All users (the reporting code for "
        "phone calls defaults to 0). Combine with a user-risk Conditional Access policy so "
        "a report blocks or challenges the account."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10039:' || ts.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            CASE WHEN lower(ts.content->'reportSuspiciousActivitySettings'->>'state') = 'enabled'
                 THEN 'Report suspicious activity is enabled for selected users only, not all users'
                 ELSE 'Report suspicious activity is not enabled (state '
                      || COALESCE(ts.content->'reportSuspiciousActivitySettings'->>'state', 'not set') || ')'
            END AS summary,
            jsonb_build_object(
                'report_suspicious_activity', ts.content->'reportSuspiciousActivitySettings',
                'note', '''default'' means disabled.'
            ) AS detail
        FROM entra_tenant_setting ts
        WHERE ts.client_id = %(client_id)s
          AND ts.setting_name = 'auth_methods_policy'
          AND jsonb_typeof(ts.content->'reportSuspiciousActivitySettings') = 'object'
          AND (lower(COALESCE(ts.content->'reportSuspiciousActivitySettings'->>'state', '')) <> 'enabled'
               OR ts.content->'reportSuspiciousActivitySettings'->'includeTarget'->>'id'
                  IS DISTINCT FROM 'all_users')
    """,
}
