"""
Plugin 11004: Service Principal Name Newly Registered on a User Account

Change Detection companion to plugin 1009 (Kerberoastable accounts).
1009 reports which user accounts currently carry an SPN and are
therefore Kerberoastable; this reports when one newly acquires that
property.

Derived from CISA advisory AA26-237A (2026-08-25), in which
Kerberoasting features in the credential-access chain against both
assessed organizations.

Restricted deliberately to user objects. Computer accounts register
and de-register SPNs constantly as a normal consequence of service
installation, domain join and cluster operations, and including them
would bury the signal. A *user* account gaining an SPN is a different
matter: it is uncommon in a steady-state directory, it is a
prerequisite for service account operation, and it is also the
mechanism behind targeted Kerberoasting -- an attacker who can write
servicePrincipalName on an account (a right frequently included in
over-broad delegations) can add an SPN, request and crack a service
ticket for it, then remove the SPN again. Note the limit of a
snapshot-based view: an SPN that is added and removed again between two
collection runs never appears in spn_edge, so this plugin only sees SPNs
still present at collection time. The transient add/remove sequence is
better caught by plugin 11008 (servicePrincipalName replication metadata
version changes) and by DC event 4738/5136 monitoring.

Severity is raised where the account is privileged, since an SPN on a
privileged account converts any domain-user foothold into an offline
attack against that privilege.

[v1.2] The summary now lists the newly registered SPNs (sorted), so a
second registration on the same account in a later run changes the
finding instead of being treated as unchanged with stale evidence. The
docstring/description no longer claim that an SPN added and removed
between runs is caught (it is not; see 11008). An SPN whose text was only
re-cased (same SPN, case-insensitively, present at the previous succeeded
run) is no longer reported as new. Disabled accounts are rated medium:
the KDC issues no service tickets for them, so the SPN is only a latent
exposure until the account is re-enabled.
"""

PLUGIN = {
    "plugin_id": 11004,
    "category": "Change Detection",
    "name": "Service Principal Name Newly Registered on a User Account",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm the SPN was registered as part of a planned service "
        "deployment. A user account that gained an SPN without a "
        "corresponding service rollout is the signature of targeted "
        "Kerberoasting, where an attacker adds an SPN, requests a "
        "service ticket, cracks it offline, and removes the SPN to "
        "erase the evidence -- so the absence of a matching change "
        "record matters more here than in most findings. Check "
        "Security event ID 4738 (user account changed) on domain "
        "controllers for who made the modification. If the "
        "registration is not accounted for, remove the SPN, rotate "
        "the account's password immediately (assume the ticket was "
        "obtained and is being cracked offline), and review who holds "
        "write access to servicePrincipalName on that object. Where "
        "the SPN is legitimate, harden the account against roasting: "
        "move it to a group Managed Service Account so the password "
        "is machine-generated and rotated automatically, or if that "
        "is not possible, set a password of 25 characters or more and "
        "ensure the account supports AES rather than RC4 (see plugin "
        "1024). Adding the account to Protected Users is not "
        "appropriate for most service accounts and can break them -- "
        "prefer gMSA."
    ),
    "control_id": "CHANGE-504",
    "framework_tags": [
        "NIST-800-53-AC-2(4)",
        "NIST-800-53-AU-6",
        "NIST-800-53-CM-3",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-DE.CM-03",
        "NIST-CSF-2.0-DE.CM-09",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "PCI-DSS-4.0-10.2.1.2",
        "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-3.11",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC6.1",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1558.003",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports service principal names newly registered on user "
        "accounts between the previous collection run and this one. "
        "Any user account with an SPN is Kerberoastable: any "
        "authenticated user can request a service ticket for it and "
        "attempt to crack the account's password offline. Beyond the "
        "standing exposure that plugin 1009 reports, the act of "
        "adding an SPN is itself an attack technique (targeted "
        "Kerberoasting) -- an attacker with write access to "
        "servicePrincipalName can add one and roast the account. Only "
        "SPNs still present at collection time are seen; an SPN added "
        "and removed between two runs is visible only through "
        "replication metadata (plugin 11008) or DC event logs. SPNs "
        "that were merely re-cased are ignored. Computer accounts are "
        "excluded because SPN churn on them is routine. Disabled "
        "accounts are rated medium. Suppressed on a client's first "
        "collection run."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id,
                   max(sr.run_id) IS NOT NULL AS have_prior
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
              AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-518'
                   OR gdo.object_sid LIKE '%%-519' OR gdo.object_sid LIKE '%%-520'
                   OR gdo.object_sid LIKE '%%-544' OR gdo.object_sid LIKE '%%-548'
                   OR gdo.object_sid LIKE '%%-549' OR gdo.object_sid LIKE '%%-550'
                   OR gdo.object_sid LIKE '%%-551')
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
        new_spns AS (
            SELECT se.object_guid,
                   array_agg(se.spn ORDER BY se.spn) AS new_spns,
                   min(se.valid_from) AS change_observed_at
            FROM spn_edge se
            CROSS JOIN prior_run prr
            WHERE se.client_id = %(client_id)s
              AND se.valid_to IS NULL
              AND se.run_id_valid_from = %(run_id)s
              -- [v1.2] A re-cased SPN closes and reopens the edge (the key
              -- holds the raw text); it is not a new registration.
              AND NOT EXISTS (
                  SELECT 1 FROM spn_edge p
                  WHERE p.client_id = se.client_id
                    AND p.object_guid = se.object_guid
                    AND lower(p.spn) = lower(se.spn)
                    AND p.run_id_valid_from <= prr.prev_run_id
                    AND (p.run_id_valid_to IS NULL
                         OR p.run_id_valid_to > prr.prev_run_id)
              )
            GROUP BY se.object_guid
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN u.is_enabled IS FALSE THEN 'medium'
                WHEN pm.via_groups IS NOT NULL OR u.admin_count = 1 THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'User account "' || COALESCE(u.sam_account_name, do2.dn_current,
                                         u.object_guid::text)
                || '" had ' || array_length(ns.new_spns, 1)
                || ' service principal name(s) registered since the previous '
                   'collection run ('
                || array_to_string(ns.new_spns, ', ')
                || '), making it Kerberoastable'
                || CASE WHEN u.is_enabled IS FALSE
                        THEN ' once re-enabled (currently disabled)'
                        ELSE '' END
                || CASE
                       WHEN pm.via_groups IS NOT NULL
                           THEN ' -- and it is an effective member of '
                                || array_to_string(pm.via_groups, ', ')
                       ELSE ''
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'distinguished_name', do2.dn_current,
                'newly_registered_spns', ns.new_spns,
                'all_current_spns', u.service_principal_names,
                'change_observed_at', ns.change_observed_at,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'privileged_via_groups', pm.via_groups,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days',
                    CASE WHEN u.pwd_last_set IS NULL THEN NULL
                         ELSE EXTRACT(DAY FROM now() - u.pwd_last_set)::int END,
                'supported_encryption_types', u.supported_encryption_types,
                'corroborating_event_id', 4738
            ) AS detail
        FROM new_spns ns
        JOIN ad_user u
            ON u.object_guid = ns.object_guid
           AND u.client_id = %(client_id)s
           AND u.valid_to IS NULL
        JOIN directory_object do2
            ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        LEFT JOIN privileged_members pm ON pm.member_guid = u.object_guid
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
    """,
}
