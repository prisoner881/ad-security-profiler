"""
Plugin 11003: New Membership in a Privileged Group Since Previous Run

Change Detection companion to the 3xxx group-hygiene plugins. Those
report the standing state -- who is in privileged groups and whether
they should be. This one reports the delta: membership that did not
exist at the previous collection and does now.

Derived from CISA advisory AA26-237A (2026-08-25), whose lessons
learned section identifies the absence of a maintained baseline as a
root cause of both organizations' failure to detect the assessments.
Privileged group membership is the single most consequential thing in
a directory that can change, and the population is small enough that
reviewing every addition is realistic in a way that reviewing every
directory change is not.

Covers nested additions, not just direct ones: an account added to a
group that is itself (transitively) inside Domain Admins gains Domain
Admin, and attackers prefer that indirection precisely because reports
built on direct membership miss it. The privileged set is computed as
the well-known administrative RIDs plus every group effectively nested
within them, then new edges into any of those groups are reported.

Legitimate privilege grants happen, so each finding is a 'warn' for
reconciliation against a change record. The severity is uniformly high
because the blast radius of an unreviewed addition here is the domain.

[v1.1] Emits one finding per member rather than one per new membership
edge. The finding is keyed on the member's GUID, so an account added to
two privileged groups in the same run produced two rows with the same
object_guid and broke the one-open-version-per-identity constraint.
Individual additions are now listed in detail.memberships (sorted by
group), and the summary names every group in a stable order; a single
addition is worded exactly as before.
"""

PLUGIN = {
    "plugin_id": 11003,
    "category": "Change Detection",
    "name": "New Membership in a Privileged Group Since Previous Run",
    "version": "1.1",
    "revision_date": "2026-10-03",
    "remediation": (
        "Match every addition to an approved request before accepting "
        "it. Security event IDs 4728, 4732 and 4756 (member added to a "
        "global, local and universal group respectively) give the "
        "authoritative actor, target and timestamp on domain "
        "controllers -- if those events are not being collected "
        "centrally, that gap is worth closing ahead of any individual "
        "finding here, since it is the only reliable record of who "
        "made the change. Pay attention to additions that arrived via "
        "nesting rather than directly: this finding's evidence names "
        "the group the member was added to and the privileged group "
        "it inherits from, and those differing is itself worth a "
        "question, because nesting is how privilege grants avoid "
        "review. Where an addition is legitimate but permanent "
        "standing privilege was not intended, move the account to a "
        "time-bound model instead -- Privileged Access Management "
        "with expiring group membership, or an approval-gated "
        "just-in-time workflow -- so that the same grant does not "
        "persist indefinitely. Where an addition cannot be accounted "
        "for, treat it as a live incident rather than a hygiene "
        "finding: remove the membership, rotate credentials for the "
        "account and for whatever account performed the addition, and "
        "review authentication activity for both."
    ),
    "control_id": "CHANGE-503",
    "framework_tags": [
        "NIST-800-53-AC-2(4)",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AU-6",
        "NIST-800-53-CM-3",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "NIST-CSF-2.0-DE.CM-09",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-10.2.1.2",
        "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC6.3",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.002",
        "MITRE-ATTCK-T1098",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports group membership edges into privileged groups that "
        "were created between the previous collection run and this "
        "one. The privileged set is the well-known administrative "
        "groups (Domain Admins, Enterprise Admins, Schema Admins, "
        "Administrators, the Operators groups, Key Admins, Cert "
        "Publishers and related) plus every group effectively nested "
        "within them, so additions that grant privilege indirectly are "
        "caught alongside direct ones. CISA's AA26-237A identifies "
        "the lack of a maintained directory baseline as a root cause "
        "of both assessed organizations failing to detect red team "
        "activity; privileged group membership is the highest-value "
        "and lowest-volume thing to baseline. Reported as a warning "
        "for reconciliation against change records. Suppressed on a "
        "client's first collection run."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT EXISTS (
                SELECT 1 FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
            ) AS have_prior
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
        -- The privileged surface is the roots themselves plus every group
        -- transitively nested inside one: an addition to a nested group
        -- confers the same privilege as an addition to the root.
        privileged_surface AS (
            SELECT pr.object_guid AS group_guid,
                   pr.sam_account_name AS group_name,
                   pr.sam_account_name AS inherits_from
            FROM privileged_roots pr
            UNION
            SELECT ng.object_guid, ng.sam_account_name, pr.sam_account_name
            FROM v_effective_group_membership vem
            JOIN privileged_roots pr ON pr.object_guid = vem.group_guid
            JOIN ad_group ng
                ON ng.object_guid = vem.member_guid
               AND ng.client_id = vem.client_id
               AND ng.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
        ),
        new_edges AS (
            SELECT gme.member_guid, gme.group_guid, gme.is_direct, gme.valid_from,
                   min(ps.group_name) AS added_to_group,
                   array_agg(DISTINCT ps.inherits_from ORDER BY ps.inherits_from)
                       AS confers_privilege_of
            FROM group_member_edge gme
            JOIN privileged_surface ps ON ps.group_guid = gme.group_guid
            WHERE gme.client_id = %(client_id)s
              AND gme.valid_to IS NULL
              AND gme.run_id_valid_from = %(run_id)s
            GROUP BY gme.member_guid, gme.group_guid, gme.is_direct, gme.valid_from
        ),
        -- [v1.1] One row per member. The finding is keyed on the member's
        -- GUID, so an account added to two privileged groups in the same run
        -- used to emit two rows with the same object_guid and collide on
        -- idx_cef_one_open_version. The individual additions now live in
        -- detail.memberships, sorted by group name so the summary and detail
        -- are stable from run to run.
        described AS (
            SELECT ne.*,
                   ne.added_to_group <> ALL (ne.confers_privilege_of) AS via_nesting,
                   '"' || ne.added_to_group || '"'
                       || CASE
                              WHEN ne.added_to_group <> ALL (ne.confers_privilege_of)
                                  THEN ' (confers the privilege of '
                                       || array_to_string(ne.confers_privilege_of, ', ')
                                       || ' through nesting)'
                              ELSE ''
                          END AS group_phrase
            FROM new_edges ne
        )
        SELECT
            'warn' AS status,
            d.member_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            COALESCE(mdo.sam_account_name, mdo.dn_current)
                || CASE
                       WHEN count(*) = 1
                           -- Single addition: wording unchanged from v1.0.
                           THEN ' was added to privileged group "' || min(d.added_to_group)
                                || '" since the previous collection run'
                                || CASE
                                       WHEN bool_or(d.via_nesting)
                                           THEN ', which confers the privilege of '
                                                || min(array_to_string(d.confers_privilege_of, ', '))
                                                || ' through nesting'
                                       ELSE ''
                                   END
                       ELSE ' was added to ' || count(*) || ' privileged groups since the '
                            'previous collection run: '
                            || string_agg(d.group_phrase, ', '
                                          ORDER BY d.added_to_group, d.group_guid)
                   END AS summary,
            jsonb_build_object(
                'member_sam_account_name', mdo.sam_account_name,
                'member_distinguished_name', mdo.dn_current,
                'member_object_class', mdo.object_class,
                'membership_count', count(*),
                'memberships', jsonb_agg(jsonb_build_object(
                    'added_to_group', d.added_to_group,
                    'confers_privilege_of', d.confers_privilege_of,
                    'is_direct_membership', d.is_direct,
                    'granted_via_nesting', d.via_nesting,
                    'change_observed_at', d.valid_from
                ) ORDER BY d.added_to_group, d.group_guid),
                'granted_via_nesting', bool_or(d.via_nesting),
                'change_observed_at', min(d.valid_from),
                'corroborating_event_ids', jsonb_build_array(4728, 4732, 4756)
            ) AS detail
        FROM described d
        JOIN directory_object mdo
            ON mdo.object_guid = d.member_guid AND mdo.client_id = %(client_id)s
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
        GROUP BY d.member_guid, mdo.sam_account_name, mdo.dn_current, mdo.object_class
    """,
}
