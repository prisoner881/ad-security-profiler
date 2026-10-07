"""
Plugin 10101: Leaked-Credential Detection on an Account with On-Premises Privilege

Joins Identity Protection 'leakedCredentials' risk detections
(entra_risk_detection, source risk_detections: detections from the last 90
days still 'atRisk' or 'confirmedCompromised'; IdentityRiskEvent.Read.All
and Entra ID P2) to the user's on-premises AD account through
entra_user.on_prem_object_guid:

- the AD account is Tier 0 (a v_privileged_principal: protected-group
  member, Tier 0 ACL control, DCSync, Tier 0 ownership, directly or via a
  group) or has adminCount = 1 -> critical. Microsoft found the user's
  current password (hash) in a leak, and with password hash sync that is
  the AD password of a domain-privileged account.
- the Entra user is synchronized from AD at all
  (on_premises_sync_enabled true, or linked to an AD object) -> high: the
  leaked password is the on-premises password too, valid for VPN, RDP,
  Kerberos and NTLM, not only for the cloud.
Cloud-only users are not reported here (plugin 10100 covers every risky
user). The detection is matched to the user by Entra object id, or by UPN
(case-insensitive) when the detection has no object id.

Why: leaked-credential detections are the rare case where Microsoft
confirms a password is in criminal hands; the hybrid join shows what that
password unlocks on-premises (MITRE T1078.002, T1078.004, T1110.004
credential stuffing).

One finding per user (object_guid = the user's Entra object id), all
detections summarised in detail. Uses current AD rows (valid_to IS NULL),
independent of the AD run id.
"""

PLUGIN = {
    "plugin_id": 10101,
    "category": "Hybrid Identity",
    "name": "Leaked-Credential Detection on an Account with On-Premises Privilege",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10101",
    "requires_sources": ["risk_detections"],
    "framework_tags": [
        "NIST-800-53-SI-4",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-DE.CM-09",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1078.002",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.004",
    ],
    "references": [
        {"title": "Microsoft: What are risk detections? (Leaked credentials)",
         "url": "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks"},
        {"title": "Microsoft Graph: riskDetection resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/riskdetection"},
        {"title": "Microsoft: Remediate risks and unblock users in Microsoft Entra ID Protection",
         "url": "https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-remediate-unblock"},
    ],
    "description": (
        "Identity Protection found the user's credentials in a leak and "
        "the user is synchronized from on-premises AD, so the leaked "
        "password is also the AD password (high); critical when the AD "
        "account is Tier 0 (privileged principal) or has adminCount = 1. "
        "One finding per user."
    ),
    "remediation": (
        "Reset the AD password immediately (twice for Tier 0 accounts to "
        "flush cached credentials), let it sync, then revoke cloud "
        "sessions (Revoke-MgUserSignInSession) and remediate the risky "
        "user. Review the account's recent on-premises logons (DC "
        "security events 4624/4768/4776) and cloud sign-ins for use of "
        "the leaked password. For Tier 0 accounts, find where the "
        "password was reused (personal services, scripts) and move the "
        "account out of sync scope: privileged AD accounts should not be "
        "synchronized. Enable a user-risk Conditional Access policy that "
        "requires a secure password change."
    ),
    "base_severity": "critical",
    "query": """
        WITH det AS (
            SELECT d.*
              FROM entra_risk_detection d
             WHERE d.client_id = %(client_id)s
               AND d.risk_event_type = 'leakedCredentials'
               AND COALESCE(d.risk_state, 'atRisk') IN ('atRisk', 'confirmedCompromised')
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = d.client_id
                              AND s.source = 'risk_detections' AND s.status = 'ok')
        ),
        det_user AS (
            SELECT eu.entra_object_id,
                   count(*) AS detections,
                   min(d.detected_at) AS first_detected_at,
                   max(d.detected_at) AS last_detected_at,
                   jsonb_agg(DISTINCT d.risk_level) FILTER (WHERE d.risk_level IS NOT NULL) AS risk_levels,
                   bool_or(d.risk_state = 'confirmedCompromised') AS confirmed
              FROM det d
              JOIN entra_user eu
                ON eu.client_id = d.client_id
               AND (eu.entra_object_id = d.entra_object_id
                    OR (d.entra_object_id IS NULL
                        AND lower(eu.user_principal_name) = lower(d.user_principal_name)))
             GROUP BY eu.entra_object_id
        ),
        priv AS (
            SELECT p.object_guid,
                   string_agg(DISTINCT p.privilege_source, ', ' ORDER BY p.privilege_source) AS sources
              FROM v_privileged_principal p
             WHERE p.client_id = %(client_id)s
             GROUP BY p.object_guid
        ),
        joined AS (
            SELECT du.*, eu.user_principal_name, eu.on_premises_sync_enabled, eu.on_prem_object_guid,
                   eu.on_premises_security_identifier, eu.account_enabled,
                   o.dn_current, u.sam_account_name, u.admin_count, u.is_enabled AS ad_is_enabled,
                   u.service_principal_names, pr.sources AS privilege_sources,
                   (pr.object_guid IS NOT NULL OR u.admin_count = 1) AS onprem_privileged
              FROM det_user du
              JOIN entra_user eu ON eu.client_id = %(client_id)s AND eu.entra_object_id = du.entra_object_id
              LEFT JOIN directory_object o
                ON o.client_id = eu.client_id AND o.object_guid = eu.on_prem_object_guid AND NOT o.is_deleted
              LEFT JOIN ad_user u
                ON u.client_id = o.client_id AND u.object_guid = o.object_guid AND u.valid_to IS NULL
              LEFT JOIN priv pr ON pr.object_guid = o.object_guid
             WHERE eu.on_premises_sync_enabled IS TRUE OR eu.on_prem_object_guid IS NOT NULL
        )
        SELECT
            'fail' AS status,
            j.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN j.onprem_privileged THEN 'critical' ELSE 'high' END AS fd_severity,
            'Leaked credentials detected for synced user '
                || COALESCE(j.user_principal_name, j.entra_object_id::text)
                || CASE WHEN j.sam_account_name IS NOT NULL
                        THEN ' (AD account ' || j.sam_account_name || ')' ELSE '' END
                || CASE WHEN j.privilege_sources IS NOT NULL
                        THEN ': the AD account is Tier 0 (' || j.privilege_sources || ')'
                        WHEN j.admin_count = 1
                        THEN ': the AD account has adminCount = 1'
                        ELSE ': the leaked password is also the on-premises password' END
                AS summary,
            jsonb_build_object(
                'entra_object_id', j.entra_object_id,
                'user_principal_name', j.user_principal_name,
                'entra_account_enabled', j.account_enabled,
                'on_premises_sync_enabled', j.on_premises_sync_enabled,
                'on_premises_security_identifier', j.on_premises_security_identifier,
                'ad_object_guid', j.on_prem_object_guid,
                'ad_distinguished_name', j.dn_current,
                'ad_sam_account_name', j.sam_account_name,
                'ad_is_enabled', j.ad_is_enabled,
                'ad_admin_count', j.admin_count,
                'ad_privilege_sources', j.privilege_sources,
                'ad_kerberoastable', COALESCE(cardinality(j.service_principal_names), 0) > 0,
                'leaked_credential_detections', j.detections,
                'first_detected_at', j.first_detected_at,
                'last_detected_at', j.last_detected_at,
                'risk_levels', j.risk_levels,
                'confirmed_compromised', j.confirmed,
                'related_plugins', jsonb_build_array(10100)
            ) AS detail
        FROM joined j
    """,
}
