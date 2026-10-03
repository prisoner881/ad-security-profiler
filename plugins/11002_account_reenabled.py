"""
Plugin 11002: Account Re-Enabled Since Previous Collection Run

Change Detection counterpart to plugin 1042. Where 1042 reports the
standing risk -- disabled accounts that still carry privilege -- this
plugin reports the event: an account that was disabled at the previous
collection and is enabled now.

Derived from CISA advisory AA26-237A (2026-08-25). In the Water and
Wastewater Systems assessment, the red team's pivot into the cloud
tenant used an AD-synced account that was disabled in Active Directory.
They re-enabled it and authenticated as it. Nothing about that
sequence requires a password reset, a group membership change, or any
other action that typically triggers review -- it is a single write to
userAccountControl, an operation delegated freely to helpdesk tiers
precisely because it reads as routine.

Re-enabling accounts is also a legitimate and common administrative
action (returning staff, seasonal roles, break-glass use), so this is a
'warn' for reconciliation rather than a 'fail'. What makes it worth
surfacing at all is that the population is small and the review is
cheap: most environments re-enable a handful of accounts per period,
and the one that matters is the one nobody can account for.

Severity is raised where the re-enabled account carries privilege, and
raised further where it has not been used in a long time -- an account
that was dormant, was disabled, and has now been switched back on is a
materially different proposition from one disabled last week by
mistake.

Implementation note: the transition is read from this project's own
temporal history rather than from an event log. ad_user rows are
versioned, so the immediately preceding version of the same object is
the authoritative "previous state," and directory_object_version ties
that version lineage to the run in which it changed.

[v1.1] Now reports a re-enable once, in the run that observed it. v1.0
compared the open ad_user row with whatever row preceded it, with no
reference to collection runs -- ad_user has no run columns of its own -- so
an account re-enabled weeks ago kept being reported on every run until some
other attribute happened to change and open a newer version. The comparison
is now anchored to the previous succeeded sync_run for the client (the
highest succeeded run_id below this one): the account's state as of that run
(the ad_user version whose directory_object_version row was open at that
run, joined by version_id) must be disabled, and the current version must
have been written by a run after it (directory_object_version
.run_id_valid_from). An account that did not exist at the previous run has
no prior state and is not reported, so newly created enabled accounts never
appear here; that remains the job of the new-account plugins.
"""

PLUGIN = {
    "plugin_id": 11002,
    "category": "Change Detection",
    "name": "Account Re-Enabled Since Previous Collection Run",
    "version": "1.1",
    "revision_date": "2026-10-03",
    "remediation": (
        "For each account, establish who re-enabled it and why, and "
        "confirm it against a ticket or documented request before "
        "accepting it. Security event ID 4722 (user account enabled) "
        "on domain controllers gives the authoritative actor and "
        "timestamp; pair it with 4738 (account changed) for the "
        "surrounding context. Accounts flagged as privileged in this "
        "finding's evidence deserve the same scrutiny as a new grant "
        "of that privilege, because that is functionally what "
        "re-enabling them was -- CISA's AA26-237A red team pivoted "
        "into a cloud tenant by re-enabling a disabled synced account "
        "rather than by adding themselves to any group. Where the "
        "account is synchronized to Entra ID, check whether the "
        "re-enable propagated to the cloud and whether any sign-ins "
        "followed. If the account should not have been re-enabled, "
        "disabling it again is not sufficient on its own: rotate its "
        "credential and review authentication activity for the "
        "intervening window, since the enabled period is exactly when "
        "it could have been used. Longer term, restrict who can write "
        "userAccountControl on privileged and service accounts -- the "
        "right to re-enable an account is the right to assume "
        "whatever privilege it retains."
    ),
    "control_id": "CHANGE-502",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1078.002"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports user accounts whose enabled state changed from "
        "disabled to enabled between the previous collection run and "
        "this one. A disabled account retains its group memberships, "
        "SPNs, SID history and ACL grants, so re-enabling it restores "
        "all of that privilege in a single write to "
        "userAccountControl -- an operation commonly delegated to "
        "helpdesk tiers because it appears routine. CISA's AA26-237A "
        "red team assessment used this exact technique, re-enabling a "
        "disabled AD-synced account to reach the organization's cloud "
        "tenant. Re-enabling accounts is also legitimate and common, "
        "so this is reported as a warning for reconciliation against "
        "change records. Severity is raised when the account holds "
        "privilege, and raised further when the account had been "
        "dormant. Each re-enable is reported once, by the first run after "
        "the previous successful collection that observes it; accounts "
        "created since that collection are not reported. Suppressed on a "
        "client's first collection run."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            -- [v1.1] The previous succeeded collection run is the baseline;
            -- NULL on a client's first run, which suppresses all output.
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        privileged_roots AS (
            SELECT g.object_guid, g.sam_account_name
            FROM ad_group g
            JOIN directory_object gdo
                ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-516'
                   OR gdo.object_sid LIKE '%%-517' OR gdo.object_sid LIKE '%%-518'
                   OR gdo.object_sid LIKE '%%-519' OR gdo.object_sid LIKE '%%-520'
                   OR gdo.object_sid LIKE '%%-521' OR gdo.object_sid LIKE '%%-526'
                   OR gdo.object_sid LIKE '%%-527' OR gdo.object_sid LIKE '%%-544'
                   OR gdo.object_sid LIKE '%%-548' OR gdo.object_sid LIKE '%%-549'
                   OR gdo.object_sid LIKE '%%-550' OR gdo.object_sid LIKE '%%-551'
                   OR gdo.object_sid LIKE '%%-552')
        ),
        privileged_members AS (
            SELECT vem.member_guid,
                   array_agg(DISTINCT pr.sam_account_name ORDER BY pr.sam_account_name)
                       AS via_groups
            FROM v_effective_group_membership vem
            JOIN privileged_roots pr ON pr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
            GROUP BY vem.member_guid
        ),
        transitions AS (
            SELECT u.object_guid, u.client_id, u.sam_account_name,
                   u.user_principal_name, u.admin_count, u.pwd_last_set,
                   u.last_logon_timestamp, u.when_created,
                   u.service_principal_names, u.version_id,
                   prev.is_enabled AS previous_is_enabled,
                   prev.valid_from AS previous_state_observed_at,
                   prev.run_id_valid_from AS previous_state_run_id,
                   cv.run_id_valid_from AS change_observed_run_id,
                   pr.prev_run_id AS baseline_run_id,
                   u.valid_from AS change_observed_at
            FROM ad_user u
            CROSS JOIN prior_run pr
            -- [v1.1] The current version must have been written since the
            -- previous succeeded run. Without this, a re-enable stayed
            -- "new" on every run until another attribute changed.
            JOIN directory_object_version cv
              ON cv.version_id = u.version_id
             AND cv.object_guid = u.object_guid
             AND cv.client_id = u.client_id
             AND cv.valid_from = u.valid_from
             AND cv.run_id_valid_from > pr.prev_run_id
             AND cv.run_id_valid_from <= %(run_id)s
            -- State as of the previous succeeded run: the version that was
            -- open at that run. An object that did not exist then has no
            -- such row, so new accounts created enabled are not reported.
            JOIN LATERAL (
                SELECT p.is_enabled, p.valid_from, pv.run_id_valid_from
                FROM ad_user p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id
                 AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id
                 AND pv.valid_from = p.valid_from
                WHERE p.object_guid = u.object_guid
                  AND p.client_id = u.client_id
                  AND p.valid_from < u.valid_from
                  AND pv.run_id_valid_from <= pr.prev_run_id
                  AND (pv.run_id_valid_to IS NULL
                       OR pv.run_id_valid_to > pr.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND u.is_enabled IS TRUE
              AND prev.is_enabled IS FALSE
        )
        SELECT
            'warn' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN pm.via_groups IS NOT NULL OR t.admin_count = 1 THEN 'critical'
                WHEN t.last_logon_timestamp IS NULL
                     OR t.last_logon_timestamp < now() - interval '180 days' THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            'Account "' || COALESCE(t.sam_account_name, do2.dn_current)
                || '" was re-enabled since the previous collection run'
                || CASE
                       WHEN pm.via_groups IS NOT NULL
                           THEN ' and is an effective member of '
                                || array_to_string(pm.via_groups, ', ')
                       WHEN t.admin_count = 1
                           THEN ' and carries the AdminSDHolder protection marker'
                       ELSE ''
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', t.sam_account_name,
                'user_principal_name', t.user_principal_name,
                'distinguished_name', do2.dn_current,
                'previous_is_enabled', t.previous_is_enabled,
                'previous_state_observed_at', t.previous_state_observed_at,
                'change_observed_at', t.change_observed_at,
                'change_observed_run_id', t.change_observed_run_id,
                'baseline_run_id', t.baseline_run_id,
                'admin_count', t.admin_count,
                'privileged_via_groups', pm.via_groups,
                'service_principal_names', t.service_principal_names,
                'pwd_last_set', t.pwd_last_set,
                'last_logon_timestamp', t.last_logon_timestamp,
                'dormant_before_reenable',
                    t.last_logon_timestamp IS NULL
                    OR t.last_logon_timestamp < now() - interval '180 days',
                'when_created', t.when_created,
                'corroborating_event_id', 4722
            ) AS detail
        FROM transitions t
        JOIN directory_object do2
            ON do2.object_guid = t.object_guid AND do2.client_id = t.client_id
        LEFT JOIN privileged_members pm ON pm.member_guid = t.object_guid
    """,
}
