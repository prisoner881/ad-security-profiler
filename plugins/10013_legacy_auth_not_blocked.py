"""
Plugin 10013: Legacy Authentication Not Blocked

Reports a tenant where legacy authentication (Exchange ActiveSync and
"other" clients: IMAP, POP3, SMTP AUTH, older Office clients, MAPI/EWS
basic auth, ...) is not blocked -- neither Security Defaults nor an enabled
Conditional Access policy blocks it for all users.

Why it matters: CISA SCuBA MS.AAD.1.1 ("Legacy authentication SHALL be
blocked"). Legacy protocols cannot perform MFA, so they are the standard
route for password spraying and credential stuffing (MITRE T1110.003) even
in tenants that otherwise enforce MFA; Microsoft reports that the vast
majority of password-spray attacks use legacy authentication.

Pass (no row) when entra_security_posture.security_defaults_enabled is true
(Security Defaults blocks legacy authentication), or when an enabled CA
policy has conditions.clientAppTypes containing both 'exchangeActiveSync'
and 'other', conditions.users.includeUsers containing 'All',
conditions.applications.includeApplications containing 'All' (the SCuBA
instructions target all resources; a block scoped to a few apps leaves the
rest open) and grant_controls.builtInControls containing 'block'.
Otherwise a high 'fail'; enabled block policies that target legacy clients
but not all users or all apps are listed in detail as partial coverage.

If the qualifying policy excludes users, groups or roles, a 'warn' row
lists the exclusions so they can be confirmed: info when only individual
users are excluded (normally the emergency-access accounts, which SCuBA
allows to be excluded), low when groups or roles are excluded (the
exclusion may cover many accounts).

Data caveats: needs the CA policy "conditions" object (entra_graph_collector
0.7.0+). Policies stored by an older collector, or with conditions null,
can't be evaluated: when any enabled policy with a 'block' grant control
lacks its conditions, the plugin returns no row rather than guess. No row
when no Entra posture was collected. A CA policy that requires MFA for
legacy clients also stops them in practice (they cannot satisfy MFA), but
SCuBA requires an explicit block, so only 'block' counts here. Plugin 10015
reports block policies left in report-only or disabled state.

Tenant-level finding: object_guid is md5('10013:' || client_id), as in
plugin 10004.

[v1.1] A policy stored without conditions (collector older than 0.7.0)
now counts as unevaluable: the check was NULL instead of FALSE, so such
policies were silently ignored and the plugin could fire on data it
cannot assess.
"""

PLUGIN = {
    "plugin_id": 10013,
    "category": "Hybrid Identity",
    "name": "Legacy Authentication Not Blocked",
    "version": "1.1",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10013",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.1.1",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "PCI-DSS-4.0-2.2.4",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-4.8",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.1.1)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Block legacy authentication with Conditional Access",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication"},
        {"title": "Microsoft: Block legacy authentication (concept)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/block-legacy-authentication"},
        {"title": "MITRE ATT&CK T1110.003: Password Spraying",
         "url": "https://attack.mitre.org/techniques/T1110/003/"},
    ],
    "description": (
        "Legacy authentication (Exchange ActiveSync and other basic-auth "
        "clients such as IMAP, POP, SMTP AUTH) is not blocked: Security "
        "Defaults is off and no enabled Conditional Access policy blocks "
        "those client app types for all users and all resources. Legacy "
        "protocols cannot do MFA, so they remain open to password spraying "
        "even where MFA is enforced (SCuBA MS.AAD.1.1). High. When a "
        "qualifying block policy exists but excludes users, groups or "
        "roles, an informational/low warning lists the exclusions. Needs "
        "the CA policy conditions (collector 0.7.0+); silent when they "
        "were not collected."
    ),
    "remediation": (
        "First check sign-in logs for remaining legacy-auth use (Entra "
        "admin center -> Sign-in logs, filter Client app = legacy "
        "clients). Then create a Conditional Access policy: Users = All "
        "users (exclude only the emergency-access accounts); Target "
        "resources = All resources; Conditions -> Client apps = Exchange "
        "ActiveSync clients and Other clients; Grant = Block access. Run "
        "it report-only briefly, then switch it On. Alternatively enable "
        "Security Defaults if the tenant does not use Conditional Access. "
        "Also disable basic authentication per protocol in Exchange "
        "Online (e.g. Set-CASMailbox -PopEnabled $false -ImapEnabled "
        "$false; Set-TransportConfig -SmtpClientAuthenticationDisabled "
        "$true). Review any exclusions listed in the finding."
    ),
    "base_severity": "high",
    "query": """
        WITH posture AS (
            SELECT sp.client_id, COALESCE(sp.security_defaults_enabled, FALSE) AS sd,
                   sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) ? 'block' AS blocks,
                   COALESCE(p->'conditions'->'clientAppTypes', '[]'::jsonb) ?& ARRAY['exchangeActiveSync', 'other'] AS legacy,
                   COALESCE(p->'conditions'->'users'->'includeUsers', '[]'::jsonb) ? 'All' AS all_users,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps,
                   COALESCE(p->'conditions'->'users'->'excludeUsers', '[]'::jsonb) AS ex_users,
                   COALESCE(p->'conditions'->'users'->'excludeGroups', '[]'::jsonb) AS ex_groups,
                   COALESCE(p->'conditions'->'users'->'excludeRoles', '[]'::jsonb) AS ex_roles
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' = 'enabled'
        ),
        qual AS (
            SELECT q.*,
                   jsonb_array_length(CASE WHEN jsonb_typeof(q.ex_users) = 'array' THEN q.ex_users ELSE '[]' END) AS n_users,
                   jsonb_array_length(CASE WHEN jsonb_typeof(q.ex_groups) = 'array' THEN q.ex_groups ELSE '[]' END)
                   + jsonb_array_length(CASE WHEN jsonb_typeof(q.ex_roles) = 'array' THEN q.ex_roles ELSE '[]' END) AS n_broad
              FROM pol q
             WHERE q.evaluable AND q.blocks AND q.legacy AND q.all_users AND q.all_apps
        ),
        best AS (
            -- the qualifying policy with the fewest exclusions (ties: name)
            SELECT * FROM qual ORDER BY n_broad, n_users, name, id LIMIT 1
        ),
        state AS (
            SELECT po.client_id, po.sd,
                   EXISTS (SELECT 1 FROM pol WHERE blocks AND NOT evaluable) AS unevaluable,
                   (SELECT jsonb_agg(name ORDER BY name) FROM pol
                     WHERE evaluable AND blocks AND legacy AND NOT (all_users AND all_apps)) AS partial
              FROM posture po
        )
        SELECT
            'fail' AS status,
            md5('10013:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Legacy authentication is not blocked -- Security Defaults is disabled and no enabled '
                || 'Conditional Access policy blocks legacy clients for all users and all resources' AS summary,
            jsonb_build_object(
                'security_defaults_enabled', s.sd,
                'partial_legacy_block_policies', s.partial
            ) AS detail
        FROM state s
        WHERE NOT s.sd AND NOT s.unevaluable
          AND NOT EXISTS (SELECT 1 FROM qual)
        UNION ALL
        SELECT
            'warn',
            md5('10013:' || s.client_id::text)::uuid,
            NULL, NULL, NULL, NULL,
            CASE WHEN b.n_broad > 0 THEN 'low' ELSE 'info' END,
            'Legacy authentication block policy "' || COALESCE(b.name, '') || '" excludes '
                || CASE WHEN b.n_broad > 0 THEN 'groups or roles' ELSE 'individual users' END
                || ' -- confirm the exclusions are emergency-access accounts only',
            jsonb_build_object(
                'policy_id', b.id,
                'policy_name', b.name,
                'excluded_users', b.ex_users,
                'excluded_groups', b.ex_groups,
                'excluded_roles', b.ex_roles
            )
        FROM state s
        CROSS JOIN best b
        WHERE NOT s.sd
          AND b.n_users + b.n_broad > 0
    """,
}
