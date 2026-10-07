"""
Plugin 10044: Stale or Never-Redeemed Guest Account

Detects enabled B2B guest users (userType Guest) that are:
- pending: externalUserState 'PendingAcceptance' for 30 days or more
  (externalUserStateChangeDateTime, or createdDateTime when that is not
  set) -- the invitation was never redeemed; or
- stale: externalUserState 'Accepted' with no sign-in activity for 90 days
  or more (latest of lastSuccessfulSignInDateTime, lastSignInDateTime,
  lastNonInteractiveSignInDateTime; or none recorded and accepted / created
  90 days or more ago). Only checked when the sign_in_activity source is
  'ok' for the client.

Why: an unredeemed invitation can be redeemed by whoever controls the
invited mailbox later (a former employee of the partner, a re-registered
domain, or an attacker who compromises that mailbox), giving them a
foothold in this tenant. Stale guests keep access to Teams, SharePoint and
application data long after the collaboration ended (MITRE ATT&CK
T1078.004, T1199 Trusted Relationship).

Data: entra_user.user_type, external_user_state,
external_user_state_changed_at, created_at (schema v42, core user read) and
the signInActivity columns (source sign_in_activity, Entra ID P1). No
requires_sources: the pending check uses core user columns. When the
collector predates v42 those columns are NULL and nothing is reported; when
sign_in_activity is not 'ok', only the pending check runs (detail says
so). Guests with a NULL external_user_state and disabled guests are not
reported.

Severity: low (warn), one row per guest (identity = Entra object id).
Summaries state the threshold, not the age.
"""

PLUGIN = {
    "plugin_id": 10044,
    "category": "Hybrid Identity",
    "name": "Stale or Never-Redeemed Guest Account",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10044",
    "framework_tags": [
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-8.2.7",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "ISO-27001-2022-A.5.19",
        "SOC2-CC6.2",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1199",
    ],
    "references": [
        {"title": "Microsoft: Properties of a Microsoft Entra B2B collaboration user",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/user-properties"},
        {"title": "Microsoft: Manage guest access with access reviews",
         "url": "https://learn.microsoft.com/en-us/entra/id-governance/manage-guest-access-with-access-reviews"},
        {"title": "Microsoft: How to manage inactive user accounts",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts"},
    ],
    "description": (
        "An enabled guest account whose invitation has been pending for 30 days or more "
        "(never redeemed: whoever later controls the invited mailbox can redeem it), or "
        "an accepted guest that has not signed in for 90 days or more (stale access to "
        "shared data). The inactivity part needs sign-in activity (Entra ID P1); without "
        "it only pending invitations are checked. Low, one finding per guest."
    ),
    "remediation": (
        "Delete pending invitations older than 30 days (Remove-MgUser for the guest "
        "object; re-invite if still needed) and remove or disable guests that have not "
        "signed in for 90 days after confirming with their sponsor. Configure Entra ID "
        "Governance access reviews for guests (all Microsoft 365 groups / applications "
        "with guest members, 'remove access if reviewers don't respond') and, if "
        "available, the inactive-guest review that removes guests who have not signed "
        "in. Restrict who can invite guests (SCuBA MS.AAD.8.2)."
    ),
    "base_severity": "low",
    "query": """
        WITH src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'sign_in_activity'
                              AND s.status = 'ok') AS sign_in_ok
        ),
        guests AS (
            SELECT u.*,
                   COALESCE(u.external_user_state_changed_at, u.created_at) AS state_since,
                   greatest(u.last_successful_sign_in_at, u.last_sign_in_at,
                            u.last_non_interactive_sign_in_at) AS last_activity,
                   src.sign_in_ok
              FROM entra_user u CROSS JOIN src
             WHERE u.client_id = %(client_id)s
               AND u.user_type = 'Guest'
               AND u.account_enabled IS TRUE
        ),
        flagged AS (
            SELECT g.*,
                   CASE WHEN g.external_user_state = 'PendingAcceptance'
                             AND g.state_since < now() - interval '30 days'
                        THEN 'pending'
                        WHEN g.external_user_state = 'Accepted'
                             AND g.sign_in_ok
                             AND (g.last_activity < now() - interval '90 days'
                                  OR (g.last_activity IS NULL
                                      AND g.state_since < now() - interval '90 days'))
                        THEN 'stale'
                   END AS kind
              FROM guests g
        )
        SELECT
            'warn' AS status,
            f.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Guest "' || COALESCE(f.user_principal_name, f.mail, f.entra_object_id::text) || '" '
                || CASE WHEN f.kind = 'pending'
                        THEN 'has not redeemed its invitation for 30 days or more'
                        WHEN f.last_activity IS NULL
                        THEN 'has never signed in and was accepted or created 90 days or more ago'
                        ELSE 'has not signed in for 90 days or more' END AS summary,
            jsonb_build_object(
                'user_principal_name', f.user_principal_name,
                'mail', f.mail,
                'display_name', f.display_name,
                'finding', f.kind,
                'external_user_state', f.external_user_state,
                'external_user_state_changed_at', f.external_user_state_changed_at,
                'created_at', f.created_at,
                'last_activity_at', f.last_activity,
                'days_since_last_activity', floor(extract(epoch FROM now() - f.last_activity) / 86400),
                'sign_in_activity_checked', f.sign_in_ok,
                'threshold_days', CASE WHEN f.kind = 'pending' THEN 30 ELSE 90 END
            ) AS detail
        FROM flagged f
        WHERE f.kind IS NOT NULL
    """,
}
