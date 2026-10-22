"""
Plugin 10029: Microsoft-Managed Conditional Access Policy Turned Off or Not Enforced

Reports Microsoft-managed Conditional Access policies (display name
starting "Microsoft-managed:", created by Microsoft in tenants that have
Conditional Access) that are not enforced:

- state 'disabled' -> fail / medium. Microsoft creates these policies in
  report-only mode and switches them On after 90 days unless an
  administrator turns them off; 'Off' is an explicit opt-out of a baseline
  Microsoft applies to every tenant (MFA for admin portals, MFA for
  per-user MFA users, blocking device code flow, blocking legacy
  authentication, risk-based reauthentication...).
- state 'enabledForReportingButNotEnforced' -> warn / low: still in its
  report-only period; it protects nothing until it is On.

Why: the Microsoft-managed policies are the floor Microsoft considers safe
for every tenant (Maester MT.1224; Microsoft's Baseline Security Mode).
Switching one off without an equivalent policy of your own leaves the gap
it was created to close; plugins 10013, 10020, 10024 and 10025 report the
resulting gaps themselves.

One finding per policy (object_guid md5('10029:' || client_id || ':' ||
policy id)). Data: entra_security_posture.ca_policies (v1.0, every
collector version). Plugin 10015 reports every other policy that is not
enforced.
"""

PLUGIN = {
    "plugin_id": 10029,
    "category": "Hybrid Identity",
    "name": "Microsoft-Managed Conditional Access Policy Turned Off or Not Enforced",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10029",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-4.1",
        "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Microsoft-managed Conditional Access policies",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies"},
        {"title": "Maester MT.1224: Microsoft-managed Conditional Access policies should not be left in report-only mode",
         "url": "https://github.com/maester365/maester/blob/main/tests/maester/entra/Test.MT.1224.md"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "A Microsoft-managed Conditional Access policy is turned off (medium) or still in "
        "report-only mode (low). Microsoft creates these policies for every tenant with "
        "Conditional Access as a security floor and enables them after 90 days unless an "
        "administrator opts out; turning one off removes that protection unless an "
        "equivalent policy of the tenant's own replaces it."
    ),
    "remediation": (
        "Entra admin center > Protection > Conditional Access > Policies, filter on "
        "'Microsoft-managed': review each listed policy and set it to On, adding exclusions "
        "(emergency-access accounts, service accounts) where needed instead of turning the "
        "whole policy off. If the tenant has its own stricter policy covering the same "
        "users, applications and condition, record that and accept the finding."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            CASE WHEN p->>'state' = 'disabled' THEN 'fail' ELSE 'warn' END AS status,
            md5('10029:' || sp.client_id::text || ':' || lower(COALESCE(p->>'id', p->>'display_name')))::uuid
                AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p->>'state' = 'disabled' THEN 'medium' ELSE 'low' END AS fd_severity,
            'Microsoft-managed Conditional Access policy "' || COALESCE(p->>'display_name', p->>'id')
                || CASE WHEN p->>'state' = 'disabled' THEN '" is turned off'
                        ELSE '" is in report-only mode (not enforced)' END AS summary,
            jsonb_build_object(
                'policy_id', p->>'id',
                'policy_name', p->>'display_name',
                'state', p->>'state',
                'grant_controls', p->'grant_controls',
                'session_controls', p->'session_controls'
            ) AS detail
        FROM entra_security_posture sp
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE WHEN jsonb_typeof(sp.ca_policies) = 'array' THEN sp.ca_policies ELSE '[]'::jsonb END) p
        WHERE sp.client_id = %(client_id)s
          AND COALESCE(p->>'display_name', '') ILIKE 'Microsoft-managed:%%'
          AND p->>'state' IN ('disabled', 'enabledForReportingButNotEnforced')
    """,
}
