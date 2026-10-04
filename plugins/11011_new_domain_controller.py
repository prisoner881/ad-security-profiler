"""
Plugin 11011: New Domain Controller Since Previous Run

Change Detection: reports computer accounts that are domain controllers
now (userAccountControl SERVER_TRUST_ACCOUNT 0x2000, or
PARTIAL_SECRETS_ACCOUNT 0x4000000 for read-only DCs) and were not at the
previous successful collection run.

Two cases, very different in meaning:
- A DC computer object created since the previous run (high). Promoting
  a DC is a planned, infrequent operation, so a new one should match a
  change record. Read-only DCs are included: an RODC whose password
  replication policy is too broad caches privileged credentials.
- An EXISTING computer account that was an ordinary computer at the
  previous run and is a DC now (critical). Legitimate promotion creates
  the account or pre-stages it immediately before dcpromo; flipping
  SERVER_TRUST_ACCOUNT on an established workstation/server account is
  the footprint of a rogue DC: DCShadow (MITRE ATT&CK T1207) registers a
  fake DC to push arbitrary changes into replication, and an attacker
  with write access to userAccountControl can turn an account they
  control into a "DC" that is then granted replication (DCSync) rights
  through Enterprise Domain Controllers / Domain Controllers membership.

Previous state is read from the ad_computer version that was current at
the previous succeeded sync_run (the 11002 lookup), and DC-ness of that
version is decided from its stored userAccountControl bits rather than
its is_domain_controller column: collectors before 0.5.15 did not set
is_domain_controller for RODCs, and the first schema v38 run rewrites
every computer, which would otherwise make every RODC look newly
promoted. Only the UAC bits are compared, so the v38 columns that appear
on every computer in that run are irrelevant here.

One row per computer. Suppressed on a client's first collection run.
Deleted objects are excluded.
"""

PLUGIN = {
    "plugin_id": 11011,
    "category": "Change Detection",
    "name": "New Domain Controller Since Previous Run",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11011",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-CM-8",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-ID.AM-01",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2", "PCI-DSS-4.0-12.5.1",
        "CIS-CSC-8-1.1", "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.5.9", "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32",
        "SOC2-CC6.1", "SOC2-CC7.2", "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1207", "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1003.006",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1207: Rogue Domain Controller",
         "url": "https://attack.mitre.org/techniques/T1207/"},
        {"title": "Microsoft: userAccountControl flags (SERVER_TRUST_ACCOUNT, PARTIAL_SECRETS_ACCOUNT)",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports computer accounts that are domain controllers (writable or "
        "read-only) now and were not at the previous successful collection run. A DC "
        "account created since then is high: promotion is a planned event and should "
        "match a change record. An existing computer account that became a DC -- "
        "SERVER_TRUST_ACCOUNT or PARTIAL_SECRETS_ACCOUNT set on an account that was "
        "an ordinary computer at the previous run -- is critical: it is the footprint "
        "of a rogue domain controller (DCShadow) or of a controlled account being "
        "turned into a DC to obtain replication rights. The previous state is judged "
        "from the stored userAccountControl bits, so the RODC detection fix in "
        "collector 0.5.15 and the schema v38 rescan do not produce false reports. "
        "Suppressed on a client's first collection run."
    ),
    "remediation": (
        "Confirm the promotion against a change record and verify the server: its "
        "nTDSDSA object under CN=Sites,CN=Configuration, its DNS records, and that it "
        "is a managed, hardened Tier 0 host. Security event IDs 4741/4742 (computer "
        "account created/changed, with the new userAccountControl) and 5137 (object "
        "created, nTDSDSA / server objects) identify who did it. For an existing "
        "computer that became a DC without a promotion, treat it as a compromise: "
        "reset userAccountControl to WORKSTATION_TRUST_ACCOUNT (4096) with "
        "Set-ADComputer <name> -Replace @{userAccountControl=4096}, remove it from "
        "Domain Controllers / Read-only Domain Controllers, delete any rogue nTDSDSA "
        "object (repadmin /showrepl to spot an unknown replication partner), "
        "investigate who held write access to the account, and rotate krbtgt twice "
        "if replication was possible. For a new RODC, review its password "
        "replication policy (msDS-RevealOnDemandGroup) and managedBy."
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
        cur AS (
            SELECT c.object_guid, c.sam_account_name, c.dns_hostname, c.operating_system,
                   c.operating_system_version, c.user_account_control, c.is_read_only_dc,
                   c.is_enabled, c.when_created, c.managed_by, c.valid_from,
                   do2.dn_current, do2.first_seen_run_id,
                   cv.run_id_valid_from AS change_run_id, pr.prev_run_id
            FROM ad_computer c
            CROSS JOIN prior_run pr
            JOIN directory_object do2
              ON do2.object_guid = c.object_guid AND do2.client_id = c.client_id
             AND NOT do2.is_deleted
            JOIN directory_object_version cv
              ON cv.version_id = c.version_id
             AND cv.object_guid = c.object_guid
             AND cv.client_id = c.client_id
             AND cv.valid_from = c.valid_from
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND pr.prev_run_id IS NOT NULL
              AND (COALESCE(c.user_account_control, 0) & (8192 | 67108864)) <> 0
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
        ),
        cmp AS (
            SELECT c.*,
                   prev.object_guid IS NOT NULL AS existed_at_prev,
                   prev.user_account_control AS prev_uac,
                   prev.sam_account_name AS prev_sam_account_name
            FROM cur c
            LEFT JOIN LATERAL (
                SELECT p.object_guid, p.user_account_control, p.sam_account_name
                FROM ad_computer p
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
        flagged AS (
            SELECT m.*,
                   (m.existed_at_prev AND m.prev_uac IS NOT NULL
                    AND (m.prev_uac & (8192 | 67108864)) = 0) AS converted,
                   (NOT m.existed_at_prev AND m.first_seen_run_id > m.prev_run_id) AS created
            FROM cmp m
        )
        SELECT
            CASE WHEN f.converted THEN 'fail' ELSE 'warn' END AS status,
            f.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN f.converted THEN 'critical' ELSE 'high' END AS fd_severity,
            CASE WHEN f.converted
                 THEN 'Existing computer account "' || COALESCE(f.sam_account_name, f.dn_current)
                      || '" became a '
                      || CASE WHEN f.is_read_only_dc THEN 'read-only domain controller'
                              ELSE 'domain controller' END
                      || ' since the previous collection run (userAccountControl 0x'
                      || to_hex(f.prev_uac) || ' -> 0x' || to_hex(f.user_account_control)
                      || ') -- possible rogue domain controller (DCShadow) or an account '
                         'converted to obtain replication rights'
                 ELSE 'New '
                      || CASE WHEN f.is_read_only_dc THEN 'read-only domain controller'
                              ELSE 'domain controller' END
                      || ' "' || COALESCE(f.sam_account_name, f.dn_current)
                      || '" appeared since the previous collection run'
            END AS summary,
            jsonb_build_object(
                'sam_account_name', f.sam_account_name,
                'dns_hostname', f.dns_hostname,
                'distinguished_name', f.dn_current,
                'change_type', CASE WHEN f.converted THEN 'existing_computer_became_dc'
                                    ELSE 'new_dc_account' END,
                'is_read_only_dc', f.is_read_only_dc,
                'user_account_control', f.user_account_control,
                'previous_user_account_control', f.prev_uac,
                'operating_system', f.operating_system,
                'operating_system_version', f.operating_system_version,
                'is_enabled', f.is_enabled,
                'when_created', f.when_created,
                'managed_by', f.managed_by,
                'change_observed_run_id', f.change_run_id,
                'baseline_run_id', f.prev_run_id,
                'change_observed_at', f.valid_from,
                'corroborating_event_ids', jsonb_build_array(4741, 4742, 5137)
            ) AS detail
        FROM flagged f
        WHERE f.converted OR f.created
    """,
}
