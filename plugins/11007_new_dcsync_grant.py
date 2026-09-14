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
"""

PLUGIN = {
    "plugin_id": 11007,
    "category": "Change Detection",
    "name": "Directory Replication Rights Newly Granted on the Domain Root",
    "version": "1.0",
    "revision_date": "2026-09-02",
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
        )
        SELECT
            'fail' AS status,
            ng.domain_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Directory replication (DCSync) rights were newly granted on the domain '
                'root to ' || COALESCE(tdo.sam_account_name, ng.trustee_sid)
                || ' ('
                || CASE
                       WHEN ng.has_get_changes AND ng.has_get_changes_all
                           THEN 'both DS-Replication-Get-Changes and -All'
                       WHEN ng.has_get_changes THEN 'DS-Replication-Get-Changes'
                       ELSE 'DS-Replication-Get-Changes-All'
                   END
                || ') -- this confers the ability to extract every credential in the '
                   'domain, including krbtgt' AS summary,
            jsonb_build_object(
                'trustee_sid', ng.trustee_sid,
                'trustee_sam_account_name', tdo.sam_account_name,
                'trustee_distinguished_name', tdo.dn_current,
                'trustee_object_class', tdo.object_class,
                'trustee_resolved', tdo.object_guid IS NOT NULL,
                'has_get_changes', ng.has_get_changes,
                'has_get_changes_all', ng.has_get_changes_all,
                'confers_full_dcsync', ng.has_get_changes AND ng.has_get_changes_all,
                'inherited_ace', ng.any_inherited,
                'change_observed_at', ng.change_observed_at,
                'corroborating_event_id', 5136
            ) AS detail
        FROM new_grants ng
        LEFT JOIN directory_object tdo
            ON tdo.object_sid = ng.trustee_sid AND tdo.client_id = %(client_id)s
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
    """,
}
