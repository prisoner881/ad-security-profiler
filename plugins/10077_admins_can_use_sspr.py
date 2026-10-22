"""
Plugin 10077: Administrators Can Use Self-Service Password Reset

Reports the tenant authorization policy setting allowedToUseSSPR = true:
users holding administrator roles may reset their own password through
self-service password reset (SSPR).

Why: for administrators, SSPR turns the recovery methods (phone, e-mail,
security questions, Authenticator) into a second way to take over the
account, outside the controls that protect their sign-in. SIM swapping or
a compromised personal mailbox resets an administrator's password;
help-desk social engineering (Scattered Spider / Octo Tempest) does the
same through the recovery flow. Microsoft's own default policy for
administrators is a two-gate policy, but turning SSPR off for them removes
the path. Purple Knight rates it high; EIDSCA AP01, EntraFalcon PAS-005,
Microsoft Zero Trust assessment 21842.

Data: entra_security_posture.authorization_policy (allowedToUseSSPR,
collected from entra_graph_collector 0.9.0; absent before, and then not
reported). fail / high, one tenant-level row (object_guid md5('10077:' ||
client_id)).
"""

PLUGIN = {
    "plugin_id": 10077,
    "category": "Hybrid Identity",
    "name": "Administrators Can Use Self-Service Password Reset",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10077",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Administrator reset policy differences (self-service password reset)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences"},
        {"title": "Microsoft Graph: authorizationPolicy resource type (allowedToUseSSPR)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
    ],
    "description": (
        "Administrators can reset their own passwords through self-service password reset "
        "(allowedToUseSSPR = true), so their recovery methods -- phone number, alternate "
        "e-mail, Authenticator -- become a second route to taking over a privileged account."
    ),
    "remediation": (
        "Microsoft Graph PowerShell: Update-MgPolicyAuthorizationPolicy -AllowedToUseSspr:$false. "
        "Administrators then reset passwords through another administrator or a "
        "privileged-access process. Keep phishing-resistant methods registered for every "
        "administrator so they do not need password recovery."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            md5('10077:' || sp.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Administrators can reset their own passwords through self-service password reset '
                || '(allowedToUseSSPR is true)' AS summary,
            jsonb_build_object('allowed_to_use_sspr', sp.authorization_policy->'allowedToUseSSPR') AS detail
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND sp.authorization_policy->'allowedToUseSSPR' = 'true'::jsonb
    """,
}
