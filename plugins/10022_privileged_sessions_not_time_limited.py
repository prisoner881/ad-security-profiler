"""
Plugin 10022: Privileged Sessions Not Time-Limited

Reports a tenant where no enabled Conditional Access policy that applies to
the highly privileged directory roles limits session lifetime with a
sign-in frequency of 12 hours or less (or "every time").

Why it matters: by default Entra ID refresh tokens live for up to 90 days
(rolling) and a browser session can persist indefinitely. Token theft
(adversary-in-the-middle phishing kits, infostealer malware harvesting
browser cookies, MITRE T1528 / T1539) gives the attacker the
administrator's session for as long as it lives. A short sign-in frequency
forces re-authentication, and a non-persistent browser session stops the
session cookie surviving the browser. Microsoft's Conditional Access
template "Sign-in frequency for administrators" and the CIS Microsoft 365
benchmark both recommend this for admin roles.

A policy counts when it is enabled, targets all resources
(applications.includeApplications contains 'All'), applies to at least one
highly privileged role (includeRoles contains the role template, or
includeUsers contains 'All') without excluding it (excludeRoles), and its
session_controls.signInFrequency has isEnabled true with frequencyInterval
'everyTime', or type 'hours' and value <= 12. (A frequency in days is
always longer than 12 hours.)

Result: one tenant-level warn / low row (object_guid =
md5('10022:' || client_id)). detail lists every enabled policy that applies
to the privileged roles with its sign-in frequency and persistent browser
setting, and whether any of them sets persistentBrowser mode 'never'.

Highly privileged roles: the same 13 roles as plugins 10014 and 11020.

Data caveats: needs the CA policy conditions and session controls
(entra_graph_collector 0.7.0+). If an enabled policy with a sign-in
frequency has no conditions object, coverage can't be evaluated and no row
is returned. No row when no Entra posture was collected.
"""

PLUGIN = {
    "plugin_id": 10022,
    "category": "Hybrid Identity",
    "name": "Privileged Sessions Not Time-Limited",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10022",
    "framework_tags": [
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1528",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Configure adaptive session lifetime policies",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime"},
        {"title": "Microsoft: Require reauthentication / sign-in frequency (Conditional Access)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "No enabled Conditional Access policy that applies to the highly "
        "privileged roles and all resources sets a sign-in frequency of 12 "
        "hours or less. Administrator sessions and refresh tokens therefore "
        "stay valid for days to weeks, so a stolen token or session cookie "
        "gives an attacker lasting administrative access."
    ),
    "remediation": (
        "Create (or extend) a Conditional Access policy: Users -> Directory "
        "roles = the highly privileged roles (exclude the emergency-access "
        "accounts); Target resources = All resources; Session -> Sign-in "
        "frequency = Periodic reauthentication, 4 to 12 hours (or 'Every "
        "time' for the most sensitive roles), and Persistent browser session "
        "= Never persistent. Test report-only first, then switch it On."
    ),
    "base_severity": "low",
    "query": """
        WITH tier0(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator')
        ),
        posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   CASE WHEN jsonb_typeof(p->'session_controls'->'signInFrequency') = 'object'
                        THEN p->'session_controls'->'signInFrequency' END AS sif,
                   CASE WHEN jsonb_typeof(p->'session_controls'->'persistentBrowser') = 'object'
                        THEN p->'session_controls'->'persistentBrowser' END AS pbrowser,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                        THEN p->'conditions'->'users'->'includeUsers' ELSE '[]'::jsonb END AS inc_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeRoles') = 'array'
                        THEN p->'conditions'->'users'->'includeRoles' ELSE '[]'::jsonb END AS inc_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' = 'enabled'
        ),
        graded AS (
            SELECT pl.*,
                   COALESCE(pl.sif->>'isEnabled' = 'true'
                            AND (pl.sif->>'frequencyInterval' = 'everyTime'
                                 OR (pl.sif->>'type' = 'hours'
                                     AND pl.sif->>'value' ~ '^[0-9]+(\\.[0-9]+)?$'
                                     AND (pl.sif->>'value')::numeric <= 12)), FALSE) AS short_sif,
                   COALESCE(pl.pbrowser->>'isEnabled' = 'true'
                            AND pl.pbrowser->>'mode' = 'never', FALSE) AS never_persistent
              FROM pol pl
        ),
        admin_pol AS (
            -- enabled, evaluable policies that apply to at least one highly privileged role
            SELECT g.*
              FROM graded g
             WHERE g.evaluable
               AND EXISTS (SELECT 1 FROM tier0 t
                            WHERE (g.inc_users ? 'All' OR g.inc_roles ? t.role_template_id)
                              AND NOT g.ex_roles ? t.role_template_id)
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM pol WHERE NOT evaluable AND sif IS NOT NULL) AS unevaluable,
                   EXISTS (SELECT 1 FROM admin_pol WHERE short_sif AND all_apps) AS covered,
                   EXISTS (SELECT 1 FROM admin_pol WHERE never_persistent) AS any_never_persistent,
                   (SELECT jsonb_agg(jsonb_build_object(
                               'policy', a.name, 'id', a.id,
                               'all_resources', a.all_apps,
                               'sign_in_frequency', a.sif,
                               'persistent_browser', a.pbrowser)
                           ORDER BY a.name, a.id)
                      FROM admin_pol a) AS policies_covering_admins
              FROM posture po
        )
        SELECT
            'warn' AS status,
            md5('10022:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Privileged sessions are not time-limited -- no enabled Conditional Access policy for the highly '
                || 'privileged roles sets a sign-in frequency of 12 hours or less' AS summary,
            jsonb_build_object(
                'policies_covering_admins', s.policies_covering_admins,
                'persistent_browser_never_set', s.any_never_persistent,
                'note', 'Also set Persistent browser session = Never persistent on the admin policy; '
                        || 'a policy counts when it targets all resources.'
            ) AS detail
        FROM state s
        WHERE NOT s.unevaluable
          AND NOT s.covered
    """,
}
