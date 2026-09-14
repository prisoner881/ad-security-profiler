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
ticket for it, then remove the SPN again. That last step means the
standing-state view in 1009 can miss the attack entirely while this
change-based view catches it.

Severity is raised where the account is privileged, since an SPN on a
privileged account converts any domain-user foothold into an offline
attack against that privilege.
"""

PLUGIN = {
    "plugin_id": 11004,
    "category": "Change Detection",
    "name": "Service Principal Name Newly Registered on a User Account",
    "version": "1.0",
    "revision_date": "2026-09-02",
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
        "ensure the account supports AES rather than RC4 (see plugins "
        "1024 and 1039). Adding the account to Protected Users is not "
        "appropriate for most service accounts and can break them -- "
        "prefer gMSA."
    ),
    "control_id": "CHANGE-504",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1558.003", "MITRE-ATTCK-T1098"],
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
        "adding an SPN is itself an attack technique -- an attacker "
        "with write access to servicePrincipalName can add one, roast "
        "the account, and remove it again, leaving no trace in a "
        "point-in-time view of the directory. Computer accounts are "
        "excluded because SPN churn on them is routine. Suppressed on "
        "a client's first collection run."
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
            WHERE se.client_id = %(client_id)s
              AND se.valid_to IS NULL
              AND se.run_id_valid_from = %(run_id)s
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
                WHEN pm.via_groups IS NOT NULL OR u.admin_count = 1 THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'User account "' || COALESCE(u.sam_account_name, do2.dn_current)
                || '" had ' || array_length(ns.new_spns, 1)
                || ' service principal name(s) registered since the previous '
                   'collection run, making it Kerberoastable'
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
