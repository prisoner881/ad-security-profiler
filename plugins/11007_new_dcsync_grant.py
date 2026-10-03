"""
Plugin 11007: Directory Replication Rights Newly Granted on the Domain Root

Change Detection companion to plugin 5001, which reports every
principal currently holding DCSync rights that is not an expected
default holder. This one reports the grant itself, including grants to
principals that 5001 would legitimately suppress.

Derived from CISA advisory AA26-237A (2026-08-25). In the Water and
Wastewater Systems assessment, an over-permissioned service account
holding AllExtendedRights over a domain controller led, via
resource-based constrained delegation, to DCSync and the krbtgt hash --
after which the team forged Golden Tickets and impersonated any user in
the domain.

Watching the grant rather than the state matters for two reasons.
First, an attacker who adds a replication ACE for an account that
already looks plausible (a service account, a synced identity, a
nested group) may not stand out in the standing-state view, because
that view has to make judgement calls about which holders are
expected. A *new* grant needs no such judgement: the correct number of
new DCSync grants in a stable directory is zero, so any nonzero result
is worth a human answer. Second, replication ACEs can be added and
removed quickly, and a point-in-time audit run on a schedule will miss
a grant that existed only between runs.

Reported at critical severity without qualification. DCSync is
equivalent to possession of the entire domain credential database,
including krbtgt, and no routine operational change should produce a
new grant of it.

[v1.1] Emits one finding per domain root rather than one per trustee.
Every grant is reported against the domain object's GUID, so two
trustees granted DCSync in the same run produced two rows with the same
object_guid and broke the one-open-version-per-identity constraint.
Individual grants are now listed in detail.grants (sorted by trustee),
and the summary names every trustee in a stable order.
"""

PLUGIN = {
    "plugin_id": 11007,
    "category": "Change Detection",
    "name": "Directory Replication Rights Newly Granted on the Domain Root",
    "version": "1.1",
    "revision_date": "2026-10-03",
    "remediation": (
        "Treat this as a suspected compromise until proven otherwise. "
        "A new grant of DS-Replication-Get-Changes or "
        "DS-Replication-Get-Changes-All on the domain root gives the "
        "named principal the ability to extract every credential in "
        "the domain, including the krbtgt key, which enables Golden "
        "Ticket forgery that survives password resets. Identify who "
        "made the change using Security event ID 5136 (directory "
        "service object modified) against the domain root object; if "
        "that event is not being collected, enable auditing of "
        "directory service changes before anything else, because it "
        "is the only authoritative record. If the grant is not "
        "accounted for by a documented change -- deploying a new "
        "directory synchronization service is the main legitimate "
        "reason -- remove the ACE, then assume the domain database "
        "was extracted: rotate the krbtgt password twice, with the "
        "interval between rotations exceeding your longest ticket "
        "lifetime, and rotate credentials for privileged and service "
        "accounts. Also review how the ACE could be written at all: "
        "the ability to modify the domain root's DACL comes from "
        "WriteDacl or full control at the domain head, so enumerate "
        "and reduce that population (see plugin 5003). Where the "
        "grant is legitimate, record the principal as a Tier 0 asset "
        "and apply the protections in plugin 10009."
    ),
    "control_id": "CHANGE-507",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1003.006", "MITRE-ATTCK-T1098",
                       "MITRE-ATTCK-T1484"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports access control entries granting directory "
        "replication rights (DS-Replication-Get-Changes and "
        "DS-Replication-Get-Changes-All, together known as DCSync) on "
        "the domain root that appeared between the previous "
        "collection run and this one. Unlike plugin 5001, which "
        "evaluates standing state and must suppress expected default "
        "holders, this reports any new grant regardless of the "
        "principal -- in a stable directory the correct number of new "
        "DCSync grants is zero, so no allowlisting judgement is "
        "required. DCSync yields the entire domain credential "
        "database including the krbtgt key; CISA's AA26-237A red team "
        "assessment reached it via an over-permissioned service "
        "account and used it to forge Golden Tickets. Suppressed on a "
        "client's first collection run."
    ),
    "base_severity": "critical",
    "query": """
        WITH prior_run AS (
            SELECT EXISTS (
                SELECT 1 FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
            ) AS have_prior
        ),
        new_grants AS (
            SELECT a.object_guid AS domain_guid,
                   a.trustee_sid,
                   bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
                       AS has_get_changes,
                   bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                       AS has_get_changes_all,
                   bool_or(a.inherited) AS any_inherited,
                   min(a.valid_from) AS change_observed_at
            FROM acl_edge a
            JOIN ad_domain d
                ON d.object_guid = a.object_guid
               AND d.client_id = a.client_id
               AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.run_id_valid_from = %(run_id)s
              AND a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                          '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
            GROUP BY a.object_guid, a.trustee_sid
        ),
        -- [v1.1] One row per domain root, not per trustee: every grant shares
        -- the domain object's GUID as its finding identity, so two trustees
        -- granted in the same run used to emit two rows with the same
        -- object_guid and collide on idx_cef_one_open_version. Per-trustee
        -- facts now live in detail.grants, sorted by trustee name/SID so the
        -- summary and detail are stable from run to run.
        described AS (
            SELECT ng.*,
                   tdo.sam_account_name, tdo.dn_current, tdo.object_class,
                   tdo.object_guid IS NOT NULL AS trustee_resolved,
                   COALESCE(tdo.sam_account_name, ng.trustee_sid) AS trustee_label,
                   CASE
                       WHEN ng.has_get_changes AND ng.has_get_changes_all
                           THEN 'both DS-Replication-Get-Changes and -All'
                       WHEN ng.has_get_changes THEN 'DS-Replication-Get-Changes'
                       ELSE 'DS-Replication-Get-Changes-All'
                   END AS rights_label
            FROM new_grants ng
            LEFT JOIN directory_object tdo
                ON tdo.object_sid = ng.trustee_sid AND tdo.client_id = %(client_id)s
        )
        SELECT
            'fail' AS status,
            d.domain_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Directory replication (DCSync) rights were newly granted on the domain '
                'root to '
                || CASE WHEN count(*) > 1 THEN count(*) || ' principals: ' ELSE '' END
                || string_agg(d.trustee_label || ' (' || d.rights_label || ')', ', '
                              ORDER BY d.trustee_label, d.trustee_sid)
                || ' -- this confers the ability to extract every credential in the '
                   'domain, including krbtgt' AS summary,
            jsonb_build_object(
                'grant_count', count(*),
                'grants', jsonb_agg(jsonb_build_object(
                    'trustee_sid', d.trustee_sid,
                    'trustee_sam_account_name', d.sam_account_name,
                    'trustee_distinguished_name', d.dn_current,
                    'trustee_object_class', d.object_class,
                    'trustee_resolved', d.trustee_resolved,
                    'has_get_changes', d.has_get_changes,
                    'has_get_changes_all', d.has_get_changes_all,
                    'confers_full_dcsync', d.has_get_changes AND d.has_get_changes_all,
                    'inherited_ace', d.any_inherited,
                    'change_observed_at', d.change_observed_at
                ) ORDER BY d.trustee_label, d.trustee_sid),
                'confers_full_dcsync', bool_or(d.has_get_changes AND d.has_get_changes_all),
                'change_observed_at', min(d.change_observed_at),
                'corroborating_event_id', 5136
            ) AS detail
        FROM described d
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
        GROUP BY d.domain_guid
    """,
}
