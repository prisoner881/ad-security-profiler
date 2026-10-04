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

[v1.2] Matches every right that confers replication: CONTROL_ACCESS
(0x100) for DS-Replication-Get-Changes / -Get-Changes-All, and, with no
object type, All Extended Rights, GenericAll (0xF01FF) or GENERIC_ALL --
v1.1 missed GenericAll/AllExtendedRights grants (BloodHound's
GenericAll/AllExtendedRights -> DCSync). Inherit-only ACEs (which do not
apply to the root) are excluded. "Newly granted" is now decided per
trustee and right against the previous succeeded run: an ACE whose mask
or inheritance flags changed (which closes and reopens its acl_edge row)
is no longer reported when the trustee already held that right at the
previous run. Effective rights combine new and existing ACEs: the finding
is critical (fail) and says the grant confers full credential extraction
only when the trustee now effectively holds both Get-Changes and
Get-Changes-All; a grant that leaves the trustee with only one of them is
high (warn) and worded as partial.
"""

PLUGIN = {
    "plugin_id": 11007,
    "category": "Change Detection",
    "name": "Directory Replication Rights Newly Granted on the Domain Root",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AU-6",
        "NIST-800-53-CM-3",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "NIST-CSF-2.0-DE.CM-09",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-10.2.1.2",
        "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.16",
        "ISO-27001-2022-A.8.32",
        "SOC2-CC6.3",
        "SOC2-CC7.2",
        "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1003.006",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1484",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports principals newly granted directory replication rights "
        "(DS-Replication-Get-Changes and DS-Replication-Get-Changes-All, "
        "together known as DCSync -- also conferred by All Extended "
        "Rights or GenericAll) on the domain root between the previous "
        "succeeded collection run and this one; a right the principal "
        "already held at the previous run is not reported again. "
        "Critical when the principal now holds both rights (full "
        "DCSync), high when it holds only one. Unlike plugin 5001, which "
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
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        -- [v1.2] Every allow ACE on the current domain root that applies to
        -- the root itself and confers a replication right, classified by
        -- right, and placed in time: open now, and/or open at the previous
        -- succeeded run.
        repl_aces AS (
            SELECT a.object_guid AS domain_guid, a.trustee_sid, a.inherited,
                   a.valid_from,
                   (a.valid_to IS NULL) AS is_current,
                   (a.run_id_valid_from > pr.prev_run_id) AS opened_since_prev,
                   (a.run_id_valid_from <= pr.prev_run_id
                    AND (a.run_id_valid_to IS NULL
                         OR a.run_id_valid_to > pr.prev_run_id)) AS open_at_prev,
                   (a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
                    AND (a.access_mask & 256) <> 0) AS r_gc,
                   (a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
                    AND (a.access_mask & 256) <> 0) AS r_gca,
                   (a.object_type_guid IS NULL
                    AND ((a.access_mask & 983551) = 983551
                         OR (a.access_mask & 256) <> 0
                         OR (a.access_mask & 268435456) <> 0)) AS r_full
            FROM acl_edge a
            JOIN ad_domain d
                ON d.object_guid = a.object_guid
               AND d.client_id = a.client_id
               AND d.valid_to IS NULL
            CROSS JOIN prior_run pr
            WHERE a.client_id = %(client_id)s
              AND pr.prev_run_id IS NOT NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND a.run_id_valid_from <= %(run_id)s
              AND (a.valid_to IS NULL
                   OR a.run_id_valid_to > pr.prev_run_id)
              AND ((a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                           '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                    AND (a.access_mask & 256) <> 0)
                   OR (a.object_type_guid IS NULL
                       AND ((a.access_mask & 983551) = 983551
                            OR (a.access_mask & 256) <> 0
                            OR (a.access_mask & 268435456) <> 0)))
        ),
        per_trustee AS (
            SELECT domain_guid, trustee_sid,
                   bool_or(is_current AND (r_gc OR r_full)) AS now_gc,
                   bool_or(is_current AND (r_gca OR r_full)) AS now_gca,
                   bool_or(is_current AND r_full) AS now_full,
                   COALESCE(bool_or(open_at_prev AND (r_gc OR r_full)), false) AS prev_gc,
                   COALESCE(bool_or(open_at_prev AND (r_gca OR r_full)), false) AS prev_gca,
                   COALESCE(bool_or(open_at_prev AND r_full), false) AS prev_full,
                   bool_or(is_current AND opened_since_prev AND inherited) AS any_inherited,
                   min(valid_from) FILTER (WHERE is_current AND opened_since_prev)
                       AS change_observed_at
            FROM repl_aces
            GROUP BY domain_guid, trustee_sid
        ),
        new_grants AS (
            SELECT pt.*,
                   (pt.now_gc AND NOT pt.prev_gc) AS new_gc,
                   (pt.now_gca AND NOT pt.prev_gca) AS new_gca,
                   (pt.now_full AND NOT pt.prev_full) AS new_full,
                   (pt.now_gc AND pt.now_gca) AS confers_full_dcsync
            FROM per_trustee pt
            WHERE pt.change_observed_at IS NOT NULL
              AND ((pt.now_gc AND NOT pt.prev_gc) OR (pt.now_gca AND NOT pt.prev_gca))
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
                       WHEN ng.new_full THEN 'GenericAll/All Extended Rights'
                       WHEN ng.new_gc AND ng.new_gca
                           THEN 'both DS-Replication-Get-Changes and -All'
                       WHEN ng.new_gc THEN 'DS-Replication-Get-Changes'
                       ELSE 'DS-Replication-Get-Changes-All'
                   END
                   || CASE WHEN ng.confers_full_dcsync THEN '; full DCSync'
                           ELSE '; partial' END AS rights_label
            FROM new_grants ng
            LEFT JOIN LATERAL (
                SELECT x.sam_account_name, x.dn_current, x.object_class, x.object_guid
                FROM directory_object x
                WHERE x.object_sid = ng.trustee_sid AND x.client_id = %(client_id)s
                ORDER BY x.is_deleted, x.object_guid
                LIMIT 1
            ) tdo ON TRUE
        )
        SELECT
            CASE WHEN bool_or(d.confers_full_dcsync) THEN 'fail' ELSE 'warn' END AS status,
            d.domain_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(d.confers_full_dcsync) THEN 'critical' ELSE 'high' END
                AS fd_severity,
            'Directory replication (DCSync) rights were newly granted on the domain '
                'root to '
                || CASE WHEN count(*) > 1 THEN count(*) || ' principals: ' ELSE '' END
                || string_agg(d.trustee_label || ' (' || d.rights_label || ')', ', '
                              ORDER BY d.trustee_label, d.trustee_sid)
                || CASE WHEN bool_or(d.confers_full_dcsync)
                        THEN ' -- this confers the ability to extract every credential '
                             'in the domain, including krbtgt'
                        ELSE ' -- partial: the principal does not hold both '
                             'Get-Changes and Get-Changes-All, which DCSync of secrets '
                             'requires'
                   END AS summary,
            jsonb_build_object(
                'grant_count', count(*),
                'grants', jsonb_agg(jsonb_build_object(
                    'trustee_sid', d.trustee_sid,
                    'trustee_sam_account_name', d.sam_account_name,
                    'trustee_distinguished_name', d.dn_current,
                    'trustee_object_class', d.object_class,
                    'trustee_resolved', d.trustee_resolved,
                    'has_get_changes', d.now_gc,
                    'has_get_changes_all', d.now_gca,
                    'has_generic_all_or_all_extended_rights', d.now_full,
                    'newly_granted_get_changes', d.new_gc,
                    'newly_granted_get_changes_all', d.new_gca,
                    'confers_full_dcsync', d.confers_full_dcsync,
                    'inherited_ace', d.any_inherited,
                    'change_observed_at', d.change_observed_at
                ) ORDER BY d.trustee_label, d.trustee_sid),
                'confers_full_dcsync', bool_or(d.confers_full_dcsync),
                'change_observed_at', min(d.change_observed_at),
                'corroborating_event_id', 5136
            ) AS detail
        FROM described d
        GROUP BY d.domain_guid
    """,
}
