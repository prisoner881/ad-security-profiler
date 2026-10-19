"""
Plugin 10074: Application Involved in a Known Third-Party Security Incident

Reports service principals (enterprise applications) of third-party
applications that a publicly reported security incident has shown to be
compromised or implicated: the vendor's own credential for the application
was stolen, so anyone holding it can authenticate AS that application in
every tenant that consented to it, with all the permissions it was granted.
One finding per service principal.

The incidents are a list in this file (KNOWN_INCIDENTS_SQL): each row names
an application id, how it is involved, the incident and the date malicious
activity began. Adding the next incident is adding rows; nothing else
changes.

Incidents listed:
- ConnectWise Cloud Backup (formerly SkyKick Backup), October 2026. A stolen
  credential of the Cloud Backup application was used from 13 October 2026 to
  obtain Microsoft Graph tokens in customer tenants (Huntress; ConnectWise
  advisory of 16 October; ConnectWise disabled seven application identities
  on 17 October). Huntress also reported suspicious activity on the related
  ConnectWise Cloud Management (SkyKick Cloud Manager) applications, among
  them a Teams application assigning itself Global Administrator and an
  Exchange Online application assigning itself Exchange Administrator.
  Cloud Backup is listed as 'compromised', the six Cloud Management
  applications as 'implicated'. Any other application published by the same
  vendor tenant (skykick.com, 3f9cd7a0-127a-4ed4-bf06-2f830d5616b7) is
  reported as 'same publisher' so the whole family is reviewed.

Severity:
- critical (fail): a 'compromised' or 'implicated' application whose service
  principal is enabled. The vendor's guidance is to disable it; while it is
  enabled the stolen credential works in this tenant.
- medium (warn): such an application already disabled, but with activity on
  or after the incident start -- it signed in, a credential was added to it,
  or it holds a directory role. Disabling it was right; that activity still
  needs investigating (sign-in and audit logs).
- low (warn): such an application disabled with no such activity: keep it
  disabled until the vendor gives re-authorisation instructions, then
  delete it or re-consent to the new identity.
- medium (warn): an enabled application from the same publisher tenant that
  is not itself on the list; review whether it is still needed. A disabled
  one is not reported.

Activity signals (evidence; the first two need the data to be read):
- last sign-in on or after the incident start (source sp_sign_in_activity;
  'sign_in_activity_collected' says whether it was read);
- a client secret or certificate on the service principal whose start date
  is on or after the incident start;
- any directory role held by the service principal (entra_directory_role_member).
The application permissions granted to it are listed for scoping
(entra_app_role_grant, source app_role_grants).

Data: entra_service_principal (source service_principals, required),
entra_app_role_grant, entra_directory_role_member, entra_collection_status.
Identity = the service principal's object id.
"""

# Known incidents: one row per application (appId). involvement is
# 'compromised' (the application's own credential was stolen and used) or
# 'implicated' (reported as involved in the same incident). incident_start
# is the earliest reported malicious activity (UTC date).
KNOWN_INCIDENTS_SQL = """
        known_app(app_id, app_name, involvement, incident, incident_start, advisory) AS (
            VALUES ('506e08f9-6e9a-4da4-942b-a099a03644ae'::uuid, 'ConnectWise Cloud Backup (SkyKick Backup)',
                    'compromised', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('2399d300-6fca-4e6a-a686-399fefe75b83'::uuid, 'ConnectWise Cloud Management (SkyKick Cloud Manager)',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('24205314-2b89-4e07-a2a4-579e898a5640'::uuid, 'ConnectWise Cloud Management - MS Teams',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('b78f6a77-d4e5-46fb-87e5-d1648bd02519'::uuid, 'ConnectWise Cloud Management - Exchange Online',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('0de14c77-b9b0-4137-9360-34878a929827'::uuid, 'ConnectWise Cloud Management - MS Graph',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('412dcf96-176d-4b3a-a1b0-4981ad66971e'::uuid, 'ConnectWise Cloud Management - Partner Center',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/'),
                   ('b2b55f5b-7758-4719-8d8f-88ae172e6bdb'::uuid, 'ConnectWise Cloud Management - SharePoint Online',
                    'implicated', 'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13',
                    'https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/')
        ),
        -- Publisher tenants (appOwnerOrganizationId) of the incidents above:
        -- their other applications are reported as 'same publisher'.
        known_publisher(owner_tenant_id, publisher, incident, incident_start) AS (
            VALUES ('3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'::uuid, 'SkyKick / ConnectWise (skykick.com)',
                    'ConnectWise Cloud Backup credential compromise', DATE '2026-10-13')
        )"""

PLUGIN = {
    "plugin_id": 10074,
    "category": "Hybrid Identity",
    "name": "Application Involved in a Known Third-Party Security Incident",
    "version": "1.0",
    "revision_date": "2026-10-19",
    "control_id": "HYBRID-10074",
    "requires_sources": ["service_principals"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-20",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-6.7",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.5.23",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1528",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "BleepingComputer: Hackers breach Microsoft 365 tenants via ConnectWise supply-chain attack",
         "url": "https://www.bleepingcomputer.com/news/security/hackers-breach-microsoft-365-tenants-via-connectwise-supply-chain-attack/"},
        {"title": "Blumira: ConnectWise Cloud Backup (SkyKick) compromise -- disable this app in every Microsoft 365 tenant you manage",
         "url": "https://www.blumira.com/blog/connectwise-cloud-backup-skykick-compromise"},
        {"title": "Microsoft: Manage access to an application (disable user sign-in for an enterprise application)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/disable-user-sign-in-portal"},
        {"title": "MITRE ATT&CK T1199: Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "A third-party application whose own credential was stolen in a "
        "publicly reported incident (currently: ConnectWise Cloud Backup / "
        "SkyKick and the related ConnectWise Cloud Management applications, "
        "October 2026) is present in the tenant. While its service principal "
        "is enabled, the attacker can authenticate as it with every permission "
        "it was granted. Critical when enabled; medium when disabled but it "
        "signed in, gained a credential or holds a directory role since the "
        "incident began; low when disabled with no such activity. Other "
        "applications from the same publisher are listed for review."
    ),
    "remediation": (
        "Disable the application now (Enterprise applications > the app > "
        "Properties > 'Enabled for users to sign-in?' = No); do not delete it "
        "yet, its configuration is evidence. Export the sign-in and audit "
        "logs before they age out (7 days on Entra ID Free) and review, from "
        "the incident start: the service principal's sign-ins (source "
        "addresses, resources), credentials added to it or to ANY other "
        "application, consent grants, and directory role assignments to "
        "applications. Remove any role it holds and any credential not "
        "issued by the vendor. Review mailbox rules, forwarding and file "
        "access for the period. Re-enable or re-consent only on the vendor's "
        "confirmed instructions, then delete the old service principal."
    ),
    "base_severity": "critical",
    "query": """
        WITH
        @KNOWN@,
        sign_in_read AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status cs
                            WHERE cs.client_id = %(client_id)s
                              AND cs.source = 'sp_sign_in_activity' AND cs.status = 'ok') AS ok
        ),
        matched AS (
            SELECT sp.*, k.app_name, k.involvement, k.incident, k.incident_start, k.advisory,
                   NULL::text AS publisher
              FROM entra_service_principal sp
              JOIN known_app k ON k.app_id = sp.app_id
             WHERE sp.client_id = %(client_id)s
            UNION ALL
            SELECT sp.*, sp.display_name, 'same publisher', p.incident, p.incident_start, NULL, p.publisher
              FROM entra_service_principal sp
              JOIN known_publisher p ON p.owner_tenant_id = sp.app_owner_organization_id
             WHERE sp.client_id = %(client_id)s
               AND NOT EXISTS (SELECT 1 FROM known_app k WHERE k.app_id = sp.app_id)
        ),
        new_creds AS (
            SELECT m.entra_object_id,
                   jsonb_agg(jsonb_build_object(
                       'type', c.cred_type, 'key_id', c.cred->>'key_id',
                       'display_name', c.cred->>'display_name',
                       'start_date_time', (c.cred->>'start_date_time')::timestamptz,
                       'end_date_time', (c.cred->>'end_date_time')::timestamptz)
                       ORDER BY (c.cred->>'start_date_time')::timestamptz, c.cred->>'key_id' COLLATE "C") AS creds
              FROM matched m
              CROSS JOIN LATERAL (
                  SELECT 'secret' AS cred_type, v AS cred
                    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.password_credentials) = 'array'
                                                   THEN m.password_credentials ELSE '[]'::jsonb END) v
                  UNION ALL
                  SELECT 'certificate', v
                    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.key_credentials) = 'array'
                                                   THEN m.key_credentials ELSE '[]'::jsonb END) v) c
             WHERE (c.cred->>'start_date_time')::timestamptz >= m.incident_start
             GROUP BY m.entra_object_id
        ),
        roles AS (
            SELECT rm.member_id AS entra_object_id,
                   jsonb_agg(DISTINCT COALESCE(rm.role_display_name, rm.role_template_id::text)
                             ORDER BY COALESCE(rm.role_display_name, rm.role_template_id::text)) AS roles
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.servicePrincipal'
             GROUP BY rm.member_id
        ),
        perms AS (
            SELECT g.principal_id AS entra_object_id,
                   jsonb_agg(DISTINCT (COALESCE(g.resource_display_name, g.resource_app_id::text)
                                       || ': ' || COALESCE(g.permission_name, g.permission_id::text)) COLLATE "C"
                             ORDER BY (COALESCE(g.resource_display_name, g.resource_app_id::text)
                                       || ': ' || COALESCE(g.permission_name, g.permission_id::text)) COLLATE "C")
                       AS permissions
              FROM entra_app_role_grant g
             WHERE g.client_id = %(client_id)s
               AND g.principal_type = 'ServicePrincipal'
             GROUP BY g.principal_id
        ),
        graded AS (
            SELECT m.*, nc.creds AS new_credentials, r.roles, p.permissions,
                   (SELECT ok FROM sign_in_read) AS sign_in_read,
                   ((SELECT ok FROM sign_in_read)
                    AND m.last_sign_in_activity_at >= m.incident_start) AS signed_in_since,
                   (m.account_enabled IS NOT FALSE) AS enabled,
                   (nc.creds IS NOT NULL OR r.roles IS NOT NULL
                    OR ((SELECT ok FROM sign_in_read) AND m.last_sign_in_activity_at >= m.incident_start))
                       AS activity
              FROM matched m
              LEFT JOIN new_creds nc ON nc.entra_object_id = m.entra_object_id
              LEFT JOIN roles r ON r.entra_object_id = m.entra_object_id
              LEFT JOIN perms p ON p.entra_object_id = m.entra_object_id
        )
        SELECT
            CASE WHEN g.involvement <> 'same publisher' AND g.enabled THEN 'fail' ELSE 'warn' END AS status,
            g.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.involvement = 'same publisher' THEN 'medium'
                 WHEN g.enabled THEN 'critical'
                 WHEN g.activity THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            CASE WHEN g.involvement = 'same publisher'
                 THEN 'Enabled application "' || COALESCE(g.display_name, g.app_id::text)
                      || '" is published by ' || g.publisher || ', the vendor of the applications in the '
                      || g.incident || ' (from ' || to_char(g.incident_start, 'YYYY-MM-DD')
                      || '); review whether it is still needed'
                 ELSE 'Application "' || COALESCE(g.display_name, g.app_name)
                      || '" (' || g.app_id::text || ') '
                      || CASE g.involvement WHEN 'compromised' THEN 'was compromised' ELSE 'is implicated' END
                      || ' in the ' || g.incident
                      || ' (from ' || to_char(g.incident_start, 'YYYY-MM-DD') || ') and its service principal is '
                      || CASE WHEN g.enabled THEN 'ENABLED: disable it now'
                              ELSE 'disabled' END
                      || CASE WHEN g.activity
                              THEN '; to investigate: it '
                                   || array_to_string(ARRAY_REMOVE(ARRAY[
                                          CASE WHEN g.signed_in_since THEN 'signed in after the incident began' END,
                                          CASE WHEN g.new_credentials IS NOT NULL
                                               THEN 'gained a credential after the incident began' END,
                                          CASE WHEN g.roles IS NOT NULL THEN 'holds a directory role' END], NULL),
                                      ', ')
                              ELSE '' END
            END AS summary,
            jsonb_build_object(
                'service_principal_id', g.entra_object_id,
                'display_name', g.display_name,
                'app_id', g.app_id,
                'app_owner_organization_id', g.app_owner_organization_id,
                'involvement', g.involvement,
                'incident', g.incident,
                'incident_start', g.incident_start,
                'advisory', g.advisory,
                'account_enabled', g.account_enabled,
                'last_sign_in_activity_at', g.last_sign_in_activity_at,
                'sign_in_activity_collected', g.sign_in_read,
                'signed_in_since_incident_start', COALESCE(g.signed_in_since, false),
                'credentials_added_since_incident_start', COALESCE(g.new_credentials, '[]'::jsonb),
                'directory_roles', COALESCE(g.roles, '[]'::jsonb),
                'application_permissions', COALESCE(g.permissions, '[]'::jsonb)
            ) AS detail
        FROM graded g
        WHERE g.involvement <> 'same publisher' OR g.enabled
    """.replace("@KNOWN@", KNOWN_INCIDENTS_SQL.strip()),
}
