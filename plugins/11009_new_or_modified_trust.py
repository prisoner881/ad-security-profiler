"""
Plugin 11009: Domain Trust Created or Modified Since Previous Run

Change Detection companion to the 7xxx trust plugins, which report the
standing state of each trust (SID filtering, selective authentication,
TGT delegation, encryption). This one reports the event: a trusted
domain object (TDO) that did not exist at the previous successful
collection, or one whose trustDirection, trustType or trustAttributes
changed since then.

Why it matters: a trust is the boundary that decides which foreign
principals can authenticate into this domain and which SIDs in their
tickets are honoured. Adding a trust, or relaxing an existing one, is a
classic persistence and escalation step (MITRE ATT&CK T1484.002, Domain
or Tenant Policy Modification: Trust Modification; T1134.005, SID-History
Injection across a trust whose SID filtering was disabled). Midnight
Blizzard / Solorigate added federation trust relationships for exactly
this reason, and CISA AA26-237A identifies the lack of a maintained
baseline as a root cause of undetected intrusions. The correct number of
unexplained trust changes in a stable forest is zero.

What is compared (and nothing else): trust_direction, trust_type and
trust_attributes of the current ad_trust version against the version
that was current at the previous succeeded sync_run (the same
"state as of the previous run" lookup as plugin 11002). The schema v38
collector adds supported_encryption_types to every TDO, which writes a
new version of every trust on its first run; that column is ignored
here, and a NULL -> value transition on any compared column counts as
"not previously collected", not as a change.

Relaxations are called out explicitly (bits of trustAttributes):
- QUARANTINED_DOMAIN (0x4, SID filtering) cleared, or TREAT_AS_EXTERNAL
  (0x40, SID history allowed across a forest trust) set;
- CROSS_ORGANIZATION (0x10, selective authentication) cleared;
- CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800) set or
  CROSS_ORGANIZATION_NO_TGT_DELEGATION (0x200) cleared (unconstrained
  delegation across the trust);
- PIM_TRUST (0x400) set (privileged-access-management shadow principals
  honoured across the trust);
- the direction gained the outbound bit (this domain now trusts the
  partner, so the partner's principals can authenticate here).

Severity: high for every new or modified trust; critical (fail) when SID
filtering was removed or SID history enabled on a trust that is outbound
from this domain (the SID-history-injection path to Enterprise Admins),
or a new outbound external/forest trust is created without SID
filtering. Within-forest (parent/child, 0x20) trusts never carry the
quarantine bit and are not held to that rule.

One row per trust (the TDO's object GUID). Suppressed on a client's
first collection run. Trusts first seen in an unaudited intermediate run
are reported by the first audited run after the previous succeeded one.
"""

PLUGIN = {
    "plugin_id": 11009,
    "category": "Change Detection",
    "name": "Domain Trust Created or Modified Since Previous Run",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11009",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-800-53-AC-4", "NIST-800-53-AC-20", "NIST-800-53-SC-7",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-8.11", "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32", "ISO-27001-2022-A.8.20",
        "ISO-27001-2022-A.8.22",
        "SOC2-CC7.2", "SOC2-CC8.1", "SOC2-CC6.6",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.002", "MITRE-ATTCK-T1134.005", "MITRE-ATTCK-T1482",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1484.002: Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
        {"title": "MITRE ATT&CK T1134.005: SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports trusted domain objects created since the previous successful "
        "collection run, and existing trusts whose direction, type or attributes "
        "changed since then. Relaxations are named explicitly: SID filtering "
        "(quarantine) removed or SID history enabled (TREAT_AS_EXTERNAL), selective "
        "authentication removed, TGT delegation enabled across the trust, PIM trust "
        "enabled, or the trust becoming outbound from this domain. Severity is high; "
        "critical when SID filtering is removed or SID history enabled on a trust "
        "outbound from this domain, or a new outbound external/forest trust lacks "
        "SID filtering -- the SID-history-injection path from the partner domain to "
        "Enterprise Admins. Only the trust direction, type and attributes are "
        "compared: the encryption-types column added by schema v38 and values "
        "collected for the first time are not treated as changes. Suppressed on a "
        "client's first collection run."
    ),
    "remediation": (
        "Confirm each new or changed trust against an approved change record. "
        "Security event IDs 4706 (new trust created), 4707 (trust removed) and 4716 "
        "(trusted domain information modified) on domain controllers identify who "
        "made the change. If the change is not accounted for, revert it and treat "
        "the partner domain as untrusted until investigated. Re-enable SID "
        "filtering with 'netdom trust <TrustingDomain> /domain:<TrustedDomain> "
        "/quarantine:yes' (external trusts) or 'netdom trust ... "
        "/enablesidhistory:no' (forest trusts); restore selective authentication "
        "with 'netdom trust ... /selectiveauth:yes'; disable TGT delegation with "
        "'netdom trust ... /EnableTGTDelegation:no'. Review the trust's current "
        "properties with Get-ADTrust -Identity <partner> | Format-List *. "
        "Restrict who can create or modify trusts: only Domain Admins / Enterprise "
        "Admins should hold rights on CN=System."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        attr_flag (bit, name) AS (
            VALUES (1, 'NON_TRANSITIVE'),
                   (2, 'UPLEVEL_ONLY'),
                   (4, 'QUARANTINED_DOMAIN (SID filtering)'),
                   (8, 'FOREST_TRANSITIVE'),
                   (16, 'CROSS_ORGANIZATION (selective authentication)'),
                   (32, 'WITHIN_FOREST'),
                   (64, 'TREAT_AS_EXTERNAL (SID history allowed)'),
                   (128, 'USES_RC4_ENCRYPTION'),
                   (512, 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'),
                   (1024, 'PIM_TRUST'),
                   (2048, 'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION')
        ),
        -- Current trust versions written since the previous succeeded run.
        cur AS (
            SELECT t.object_guid, t.trust_partner, t.trust_direction, t.trust_type,
                   t.trust_attributes, t.sid_filtering_enabled, t.valid_from,
                   do2.dn_current, do2.first_seen_run_id,
                   cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_trust t
            CROSS JOIN prior_run pr
            JOIN directory_object do2
              ON do2.object_guid = t.object_guid AND do2.client_id = t.client_id
             AND NOT do2.is_deleted
            JOIN directory_object_version cv
              ON cv.version_id = t.version_id
             AND cv.object_guid = t.object_guid
             AND cv.client_id = t.client_id
             AND cv.valid_from = t.valid_from
            WHERE t.client_id = %(client_id)s
              AND t.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        cmp AS (
            SELECT c.*,
                   prev.trust_direction AS prev_direction,
                   prev.trust_type AS prev_type,
                   prev.trust_attributes AS prev_attributes,
                   prev.sid_filtering_enabled AS prev_sid_filtering,
                   prev.object_guid IS NOT NULL AS existed_at_prev
            FROM cur c
            -- The version that was current at the previous succeeded run.
            LEFT JOIN LATERAL (
                SELECT p.object_guid, p.trust_direction, p.trust_type,
                       p.trust_attributes, p.sid_filtering_enabled
                FROM ad_trust p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id
                 AND pv.object_guid = p.object_guid
                 AND pv.client_id = p.client_id
                 AND pv.valid_from = p.valid_from
                WHERE p.object_guid = c.object_guid
                  AND p.client_id = %(client_id)s
                  AND p.valid_from < c.valid_from
                  AND pv.run_id_valid_from <= c.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > c.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
        ),
        classified AS (
            SELECT m.*,
                   NOT m.existed_at_prev AND m.first_seen_run_id > m.prev_run_id AS is_new,
                   (m.existed_at_prev AND m.prev_direction IS NOT NULL
                    AND m.trust_direction IS DISTINCT FROM m.prev_direction) AS dir_changed,
                   (m.existed_at_prev AND m.prev_type IS NOT NULL
                    AND m.trust_type IS DISTINCT FROM m.prev_type) AS type_changed,
                   (m.existed_at_prev AND m.prev_attributes IS NOT NULL
                    AND m.trust_attributes IS DISTINCT FROM m.prev_attributes) AS attr_changed,
                   COALESCE(m.trust_attributes, 0) AS a_now,
                   COALESCE(m.prev_attributes, 0) AS a_prev,
                   (COALESCE(m.trust_direction, 0) & 2) <> 0 AS is_outbound
            FROM cmp m
        ),
        changed AS (
            SELECT c.*,
                   array_remove(ARRAY[
                       CASE WHEN c.attr_changed AND (c.a_prev & 4) <> 0 AND (c.a_now & 4) = 0
                            THEN 'SID filtering (quarantine) removed' END,
                       CASE WHEN c.attr_changed AND (c.a_prev & 64) = 0 AND (c.a_now & 64) <> 0
                            THEN 'SID history enabled across the forest trust (TREAT_AS_EXTERNAL set)' END,
                       CASE WHEN c.attr_changed AND (c.a_prev & 16) <> 0 AND (c.a_now & 16) = 0
                            THEN 'selective authentication removed' END,
                       CASE WHEN c.attr_changed
                                 AND (((c.a_prev & 2048) = 0 AND (c.a_now & 2048) <> 0)
                                      OR ((c.a_prev & 512) <> 0 AND (c.a_now & 512) = 0))
                            THEN 'TGT delegation enabled across the trust' END,
                       CASE WHEN c.attr_changed AND (c.a_prev & 1024) = 0 AND (c.a_now & 1024) <> 0
                            THEN 'PIM trust enabled' END,
                       CASE WHEN c.dir_changed AND (COALESCE(c.prev_direction, 0) & 2) = 0
                                 AND c.is_outbound
                            THEN 'trust became outbound (this domain now trusts the partner)' END
                   ], NULL) AS relaxations,
                   -- SID-history-injection exposure created by this change.
                   (c.is_outbound AND (c.a_now & 32) = 0
                    AND ((c.existed_at_prev AND c.attr_changed
                          AND (((c.a_prev & 4) <> 0 AND (c.a_now & 4) = 0)
                               OR ((c.a_prev & 64) = 0 AND (c.a_now & 64) <> 0)))
                         OR (c.is_new
                             AND (((c.a_now & 8) = 0 AND (c.a_now & 4) = 0
                                   AND COALESCE(c.trust_type, 0) <> 3)
                                  OR (c.a_now & 72) = 72))))
                       AS sid_filtering_exposed
            FROM classified c
            WHERE c.is_new OR c.dir_changed OR c.type_changed OR c.attr_changed
        ),
        labelled AS (
            SELECT ch.*,
                   CASE ch.trust_direction WHEN 0 THEN 'disabled' WHEN 1 THEN 'inbound'
                        WHEN 2 THEN 'outbound' WHEN 3 THEN 'bidirectional'
                        ELSE COALESCE(ch.trust_direction::text, 'unknown') END AS dir_now,
                   CASE ch.prev_direction WHEN 0 THEN 'disabled' WHEN 1 THEN 'inbound'
                        WHEN 2 THEN 'outbound' WHEN 3 THEN 'bidirectional'
                        ELSE COALESCE(ch.prev_direction::text, 'unknown') END AS dir_prev,
                   CASE ch.trust_type WHEN 1 THEN 'downlevel (NT4)' WHEN 2 THEN 'uplevel (Active Directory)'
                        WHEN 3 THEN 'MIT Kerberos realm' WHEN 4 THEN 'DCE'
                        ELSE COALESCE(ch.trust_type::text, 'unknown') END AS type_now,
                   CASE ch.prev_type WHEN 1 THEN 'downlevel (NT4)' WHEN 2 THEN 'uplevel (Active Directory)'
                        WHEN 3 THEN 'MIT Kerberos realm' WHEN 4 THEN 'DCE'
                        ELSE COALESCE(ch.prev_type::text, 'unknown') END AS type_prev,
                   (SELECT string_agg(f.name, ', ' ORDER BY f.bit) FROM attr_flag f
                     WHERE (ch.a_now & f.bit) <> 0) AS attrs_now,
                   (SELECT string_agg(f.name, ', ' ORDER BY f.bit) FROM attr_flag f
                     WHERE (ch.a_now & f.bit) <> 0 AND (ch.a_prev & f.bit) = 0) AS attrs_added,
                   (SELECT string_agg(f.name, ', ' ORDER BY f.bit) FROM attr_flag f
                     WHERE (ch.a_prev & f.bit) <> 0 AND (ch.a_now & f.bit) = 0) AS attrs_removed
            FROM changed ch
        )
        SELECT
            CASE WHEN l.sid_filtering_exposed THEN 'fail' ELSE 'warn' END AS status,
            l.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN l.sid_filtering_exposed THEN 'critical' ELSE 'high' END AS fd_severity,
            CASE WHEN l.is_new
                 THEN 'Trust with "' || COALESCE(l.trust_partner, l.dn_current)
                      || '" was created since the previous collection run (direction '
                      || l.dir_now || ', type ' || l.type_now
                      || ', attributes: ' || COALESCE(l.attrs_now, 'none') || ')'
                      || CASE WHEN l.sid_filtering_exposed
                              THEN ' -- it is outbound from this domain without SID filtering, '
                                   'so SIDs injected in the partner domain are honoured here'
                              ELSE '' END
                 ELSE 'Trust with "' || COALESCE(l.trust_partner, l.dn_current)
                      || '" was modified since the previous collection run: '
                      || array_to_string(array_remove(ARRAY[
                             CASE WHEN l.dir_changed
                                  THEN 'direction ' || l.dir_prev || ' -> ' || l.dir_now END,
                             CASE WHEN l.type_changed
                                  THEN 'type ' || l.type_prev || ' -> ' || l.type_now END,
                             CASE WHEN l.attr_changed
                                  THEN 'attributes 0x' || to_hex(l.a_prev) || ' -> 0x' || to_hex(l.a_now)
                                       || ' (' || array_to_string(array_remove(ARRAY[
                                              CASE WHEN l.attrs_added IS NOT NULL
                                                   THEN 'set: ' || l.attrs_added END,
                                              CASE WHEN l.attrs_removed IS NOT NULL
                                                   THEN 'cleared: ' || l.attrs_removed END
                                          ], NULL), '; ') || ')' END
                         ], NULL), '; ')
                      || CASE WHEN cardinality(l.relaxations) > 0
                              THEN ' -- relaxed: ' || array_to_string(l.relaxations, ', ')
                              ELSE '' END
            END AS summary,
            jsonb_build_object(
                'trust_partner', l.trust_partner,
                'distinguished_name', l.dn_current,
                'change_type', CASE WHEN l.is_new THEN 'created' ELSE 'modified' END,
                'trust_direction', l.trust_direction,
                'previous_trust_direction', l.prev_direction,
                'trust_type', l.trust_type,
                'previous_trust_type', l.prev_type,
                'trust_attributes', l.trust_attributes,
                'previous_trust_attributes', l.prev_attributes,
                'attributes_now', l.attrs_now,
                'attributes_set', l.attrs_added,
                'attributes_cleared', l.attrs_removed,
                'sid_filtering_enabled', l.sid_filtering_enabled,
                'previous_sid_filtering_enabled', l.prev_sid_filtering,
                'relaxations', to_jsonb(l.relaxations),
                'sid_history_injection_exposure', l.sid_filtering_exposed,
                'change_observed_run_id', l.change_run_id,
                'baseline_run_id', l.prev_run_id,
                'change_observed_at', l.valid_from,
                'corroborating_event_ids', jsonb_build_array(4706, 4716)
            ) AS detail
        FROM labelled l
    """,
}
