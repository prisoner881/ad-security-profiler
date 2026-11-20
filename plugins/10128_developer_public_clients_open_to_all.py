"""
Plugin 10128: Microsoft Developer Tools Usable by Every User (AuthCodeFix / ConsentFix Phishing)

"AuthCodeFix" / "ConsentFix" phishing (exploited since December 2025;
Christopher Brumm, "A second look at AuthCodeFix", 2026-10-31): the victim
is talked into signing in to a pre-consented Microsoft first-party public
client that redirects to http://localhost -- Azure CLI, Azure PowerShell,
Visual Studio Code, Visual Studio, the Teams PowerShell module -- and
pasting the resulting URL, which carries the authorization code, back to
the attacker, who redeems it for the user's tokens. PKCE does not help
(the attacker started the flow), MFA has already been satisfied, and the
code's shorter lifetime (about 60 seconds) is beaten by automated kits.
Brumm's first mitigation: "Require user assignment on the first-party apps
the attack relies on ... An unassigned user can't complete the
authorization at all", plus Conditional Access requiring a compliant
network.

Checked applications (appIds from the community Microsoft first-party
application list, merill/microsoft-info): Microsoft Azure CLI
04b07795-8ddb-461a-bbee-02f9e1bf7b46, Microsoft Azure PowerShell
1950a258-227b-4e31-a9cf-717495945fc2, Visual Studio Code
aebc6443-996d-45c2-90f0-388ff96faa56. An application is open when its
service principal does not require assignment
(appRoleAssignmentRequired false) or does not exist in the tenant (it is
created on first use, without assignment required).

One finding per tenant (identity md5('10128:' || client_id)), status
'warn', low: a hardening recommendation that fires in most tenants.

Data: entra_service_principal. Related: 10020 (device code flow not
blocked), 10016 (user consent).
"""

PLUGIN = {
    "plugin_id": 10128,
    "category": "Hybrid Identity",
    "name": "Microsoft Developer Tools Usable by Every User (AuthCodeFix / ConsentFix Phishing)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYBRID-10128",
    "requires_sources": ["service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1528",
        "MITRE-ATTCK-T1566.002",
    ],
    "references": [
        {"title": "Christopher Brumm: A second look at AuthCodeFix (2026-10-31)",
         "url": "https://chris-brumm.com/2026/10/A-second-look-at-AuthCodeFix/"},
        {"title": "Microsoft Learn: Restrict a Microsoft Entra app to a set of users (assignment required)",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/howto-restrict-your-app-to-a-set-of-users"},
        {"title": "Microsoft first-party application IDs (community list, merill/microsoft-info)",
         "url": "https://github.com/merill/microsoft-info"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "Azure CLI, Azure PowerShell or Visual Studio Code can be used by every user (their service "
        "principals do not require assignment, or do not exist yet). \"AuthCodeFix\" phishing, "
        "exploited since December 2025, tricks users into signing in to these tools and pasting "
        "the sign-in code to the attacker, who takes their tokens. Requiring assignment limits "
        "them to the people who need them. Low: a hardening recommendation."
    ),
    "remediation": (
        "For each tool listed: create its service principal if it does not exist "
        "(New-MgServicePrincipal -AppId <appId>), set \"Assignment required\" to Yes (Enterprise "
        "applications -> the app -> Properties), and assign the groups of administrators and "
        "developers who use it. Do the same for Visual Studio and the Teams PowerShell module if "
        "they are used. Add a Conditional Access policy requiring a compliant network (Global "
        "Secure Access) for all users and resources, which blocks redemption of a stolen code, and "
        "block device code flow (plugin 10020)."
    ),
    "base_severity": "low",
    "query": """
        WITH
        tool(app_id, tool_name) AS (
            VALUES ('04b07795-8ddb-461a-bbee-02f9e1bf7b46'::uuid, 'Microsoft Azure CLI'),
                   ('1950a258-227b-4e31-a9cf-717495945fc2'::uuid, 'Microsoft Azure PowerShell'),
                   ('aebc6443-996d-45c2-90f0-388ff96faa56'::uuid, 'Visual Studio Code')
        ),
        state AS (
            SELECT t.tool_name, t.app_id, sp.entra_object_id, sp.app_role_assignment_required,
                   CASE WHEN sp.entra_object_id IS NULL THEN 'no service principal (created on first use)'
                        WHEN sp.app_role_assignment_required IS TRUE THEN 'assignment required'
                        ELSE 'assignment not required' END AS state,
                   sp.entra_object_id IS NULL OR sp.app_role_assignment_required IS NOT TRUE AS open
              FROM tool t
              LEFT JOIN entra_service_principal sp
                     ON sp.client_id = %(client_id)s AND sp.app_id = t.app_id
        ),
        summary AS (
            SELECT count(*) FILTER (WHERE open) AS open_count,
                   string_agg(tool_name, ', ' ORDER BY tool_name) FILTER (WHERE open) AS open_text,
                   jsonb_agg(jsonb_build_object('tool', tool_name, 'app_id', app_id,
                                                'service_principal_id', entra_object_id, 'state', state)
                             ORDER BY tool_name) AS tools
              FROM state
        )
        SELECT
            'warn' AS status,
            md5('10128:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Every user can sign in to ' || s.open_text || ' (no user assignment required): the tools '
                || 'targeted by AuthCodeFix / ConsentFix phishing, which steals the sign-in code' AS summary,
            jsonb_build_object(
                'tools', s.tools,
                'not_checked', 'Visual Studio and the Teams PowerShell module are also abused; their '
                               'application IDs are not checked here.'
            ) AS detail
        FROM summary s
        WHERE s.open_count > 0
          AND EXISTS (SELECT 1 FROM entra_service_principal x WHERE x.client_id = %(client_id)s)
    """,
}
