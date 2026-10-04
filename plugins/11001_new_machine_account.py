"""
Plugin 11001: Machine Account Created Since Previous Collection Run

First plugin in the 11xxx Change Detection category, derived from CISA
advisory AA26-237A (2026-08-25). The advisory's central lesson is not
about any individual misconfiguration -- every AD weakness it describes
is long-standing and well documented -- but about detection: both
assessed organizations lacked a maintained baseline, so routine alerts
and false positives obscured the red team's activity, and neither
detected the intrusion.

This project's schema is bitemporal (valid_from/valid_to, run-scoped
version lineage in directory_object_version, first_seen_run_id on
directory_object) but every plugin before this category queried only
the present state. Change detection asks a different and complementary
question: not "is this domain misconfigured" but "what changed since
the last time we looked." Most of the red team's directory-visible
actions in AA26-237A produce exactly one such delta.

Machine account creation is the highest-signal of those. In the Water
and Wastewater Systems assessment, the red team abused a
MachineAccountQuota of 1000 to create a computer account -- named to
resemble a legitimate host -- and fed it into a misconfigured
certificate template. Plugin 4009 reports that the quota permits this;
this plugin reports that it happened.

Not every new computer object is hostile: ordinary provisioning
creates them constantly. This is deliberately a 'warn', intended to be
triaged against a change record rather than treated as an incident on
its own. Severity is raised when MachineAccountQuota is non-zero, since
that is the condition under which any domain user -- not just a
provisioning system -- could have created it.

Suppressed entirely on a client's first collection run, where every
object is new by definition.

[v1.1] Severity no longer rises on MachineAccountQuota alone (the default
quota is 10, so that made nearly every routinely provisioned computer
"high"). It is now: high when the new object shows an attack-path signal
-- it holds resource-based constrained delegation rights to another object
(the classic MAQ -> RBCD chain), it is trusted for unconstrained
delegation, it carries a userPrincipalName (the plugin 1043 path), or its
dNSHostName duplicates another computer's (Certifried, CVE-2022-26923);
medium when the quota is non-zero; low otherwise. Group/standalone managed
service accounts (computer subclasses, identified by
msDS-GroupMSAMembership or the Managed Service Accounts container) are
labelled as such and rated low unless a signal applies -- they cannot be
created through the quota. Scope note: the window is "first seen in the
audited run"; if adaudit is not run for some sync run, objects first seen
in that run are never reported, and each finding closes as remediated on
the next run by design (it is an event, not a state).
"""

PLUGIN = {
    "plugin_id": 11001,
    "category": "Change Detection",
    "name": "Machine Account Created Since Previous Collection Run",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Reconcile each new computer account against your provisioning "
        "records: an account created by an imaging or MDM workflow "
        "should have a corresponding build ticket, and one that does "
        "not is worth a direct answer before it is dismissed. Pay "
        "particular attention to names that closely resemble existing "
        "hosts but do not match your naming convention exactly -- "
        "CISA's AA26-237A red team deliberately named its rogue "
        "machine account to blend into the environment, and near-miss "
        "naming is the cheapest available signal. Confirm who created "
        "the account by reading the mS-DS-CreatorSID attribute on the "
        "object directly (Get-ADComputer <name> -Properties "
        "mS-DS-CreatorSID); if the creator is an ordinary user rather "
        "than a provisioning service or domain administrator, treat "
        "the account as suspect and investigate that user's activity. "
        "Correlate with Security event ID 4741 (computer account "
        "created) on domain controllers for the authoritative record "
        "of who created it and from where. If MachineAccountQuota is "
        "non-zero (see plugin 4009), set it to 0 and delegate computer "
        "creation to a specific provisioning group instead -- that "
        "single change removes the ability of any domain user to "
        "create the account this finding describes."
    ),
    "control_id": "CHANGE-501",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1136.002", "MITRE-ATTCK-T1098"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports computer accounts that appeared in the directory "
        "between the previous collection run and this one. Rogue "
        "machine account creation is the entry point for several "
        "current attack paths -- resource-based constrained "
        "delegation, and certificate template abuse where a "
        "machine account is used to request a certificate for a "
        "higher-privileged principal. CISA's AA26-237A red team "
        "assessment created exactly such an account, named to resemble "
        "a legitimate host, after finding MachineAccountQuota set to "
        "1000. Ordinary provisioning also creates computer accounts, "
        "so this is reported as a warning for reconciliation against "
        "change records, not as evidence of compromise. Severity is "
        "high when the new object shows an attack-path signal (holds "
        "RBCD rights to another object, unconstrained delegation, a "
        "userPrincipalName, or a dNSHostName duplicating another "
        "computer's), medium when MachineAccountQuota is non-zero, and "
        "low otherwise; managed service accounts are labelled and rated "
        "low. Suppressed on a client's first collection run; objects "
        "first seen in a sync run that was never audited are not "
        "reported."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            SELECT EXISTS (
                SELECT 1 FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
            ) AS have_prior
        ),
        domain_quota AS (
            SELECT max(d.machine_account_quota) AS maq
            FROM ad_domain d
            WHERE d.valid_to IS NULL AND d.client_id = %(client_id)s
        ),
        new_computer AS (
            SELECT c.*, do2.dn_current, do2.first_seen_run_id,
                   -- [v1.1] gMSA / sMSA objects are computer subclasses:
                   -- identified by msDS-GroupMSAMembership or their container.
                   (do2.dn_current ILIKE '%%,CN=Managed Service Accounts,%%'
                    OR EXISTS (SELECT 1 FROM directory_object_version dov
                                WHERE dov.object_guid = c.object_guid
                                  AND dov.client_id = c.client_id
                                  AND dov.valid_to IS NULL
                                  AND dov.attributes_full->>'msDS-GroupMSAMembership' IS NOT NULL))
                       AS is_managed_service_account,
                   -- [v1.1] Signals that the new object is being used in an
                   -- attack path rather than ordinary provisioning.
                   array_remove(ARRAY[
                       CASE WHEN EXISTS (
                                SELECT 1 FROM delegation_edge de
                                 WHERE de.client_id = c.client_id AND de.valid_to IS NULL
                                   AND de.delegation_type = 'rbcd'
                                   AND de.source_guid = c.object_guid)
                            THEN 'holds resource-based constrained delegation rights to another object' END,
                       CASE WHEN c.unconstrained_delegation IS TRUE
                            THEN 'is trusted for unconstrained delegation' END,
                       CASE WHEN c.user_principal_name IS NOT NULL
                            THEN 'has a userPrincipalName set' END,
                       CASE WHEN c.dns_hostname IS NOT NULL AND EXISTS (
                                SELECT 1 FROM ad_computer o
                                 WHERE o.client_id = c.client_id AND o.valid_to IS NULL
                                   AND o.object_guid <> c.object_guid
                                   AND lower(o.dns_hostname) = lower(c.dns_hostname))
                            THEN 'has a dNSHostName duplicating another computer''s' END
                   ], NULL) AS signals
            FROM ad_computer c
            JOIN directory_object do2
                ON do2.object_guid = c.object_guid AND do2.client_id = c.client_id
            CROSS JOIN prior_run pr
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND pr.have_prior
              AND do2.first_seen_run_id = %(run_id)s
              AND NOT c.is_domain_controller
              AND NOT do2.is_deleted
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN cardinality(c.signals) > 0 THEN 'high'
                 WHEN c.is_managed_service_account THEN 'low'
                 WHEN COALESCE(dq.maq, 0) > 0 THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            CASE WHEN c.is_managed_service_account THEN 'Managed service account "'
                 ELSE 'Computer account "' END
                || COALESCE(c.sam_account_name, c.dn_current)
                || '" was created since the previous collection run'
                || CASE WHEN COALESCE(dq.maq, 0) > 0 AND NOT c.is_managed_service_account
                        THEN ' (MachineAccountQuota is ' || dq.maq
                             || ', so any authenticated user could have created it)'
                        ELSE '' END
                || CASE WHEN cardinality(c.signals) > 0
                        THEN '; it ' || array_to_string(c.signals, ', ')
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'distinguished_name', c.dn_current,
                'operating_system', c.operating_system,
                'operating_system_version', c.operating_system_version,
                'when_created', c.when_created,
                'first_seen_run_id', c.first_seen_run_id,
                'is_enabled', c.is_enabled,
                'is_managed_service_account', c.is_managed_service_account,
                'unconstrained_delegation', c.unconstrained_delegation,
                'user_principal_name', c.user_principal_name,
                'attack_path_signals', to_jsonb(c.signals),
                'machine_account_quota', dq.maq,
                'created_by_attribute_note',
                    'mS-DS-CreatorSID is not collected by this project; read it '
                    'directly from the object to identify the creator'
            ) AS detail
        FROM new_computer c
        CROSS JOIN domain_quota dq
    """,
}
