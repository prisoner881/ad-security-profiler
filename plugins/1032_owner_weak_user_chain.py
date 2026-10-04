"""
Plugin 1032: Domain Root or AdminSDHolder Owned by an Independently Weak User Account

Refines plugin 5006 (any unexpected owner) with a specific, higher-
urgency angle: the owner isn't just unrecognized, it's a user account
that is ALSO independently exploitable -- dormant, Kerberoastable,
AS-REP roastable, or PASSWD_NOTREQD. An object's owner can always
rewrite its ACL to grant themselves anything, regardless of what
explicit ACEs currently say, so an owner that's easy to compromise (or
long-abandoned and unlikely to be missed if compromised) is a
meaningfully worse case than an unexpected-but-otherwise-solid owner.

[v1.2] Emits one finding per owning user account rather than one per owned
object. A user account owning both the domain root and AdminSDHolder produced
two rows with the same object_guid and broke the one-open-version-per-
identity constraint; both are now named in one summary (in a stable
order) and listed in detail.object_dns, which replaces detail.object_dn.

[v1.3] A disabled owner is no longer called Kerberoastable, AS-REP
roastable, PASSWD_NOTREQD or dormant (it cannot authenticate at all);
its weakness is reported as 'disabled' at 'high' -- whoever re-enables
it gets the ownership. The weakness list is aggregated in a fixed,
explicit order; the domain-root test is client-scoped and deleted owner
objects are ignored. detail gains is_enabled.
"""

PLUGIN = {
    "plugin_id": 1032,
    "category": "User Accounts",
    "name": "Domain Root or AdminSDHolder Owned by an Independently Weak User Account",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Take ownership back to a recognized default holder immediately "
        "(see plugin 5006's remediation) -- this is a higher-priority "
        "case than an ordinary unexpected-owner finding, since the "
        "owner itself has an independent, exploitable weakness. "
        "Investigate whether this account's own weakness has already "
        "been exploited to reach this ownership in the first place, "
        "not just how to fix the ownership going forward."
    ),
    "control_id": "CHAIN-106",
    "framework_tags": [
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.3",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.18",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "Refines plugin 5006 (any unexpected owner of the domain root "
        "or AdminSDHolder) with a specific, higher-urgency angle: the "
        "owner is a user account that is ALSO independently exploitable "
        "via at least one of being disabled (rated high: re-enabling "
        "it restores the ownership), dormancy (90+ days since last logon, or "
        "never logged on), Kerberoasting, AS-REP roasting, or a blank/"
        "not-required password. An owner can always rewrite an object's "
        "ACL to grant themselves anything regardless of current "
        "explicit permissions, so an easily-compromised (or long-"
        "abandoned) owner is meaningfully worse than an unexpected but "
        "otherwise well-secured one."
    ),
    "base_severity": "critical",
    "query": """
        -- [v1.2] One row per owning user account. The finding is keyed on the
        -- owner's GUID, so a user account owning both the domain root and
        -- AdminSDHolder (or more than one domain root) used to emit one row
        -- per owned object with the same object_guid and collide on
        -- idx_cef_one_open_version. Owned objects are now aggregated, sorted,
        -- into the summary and detail.object_dns. The owner is also resolved
        -- with a join rather than a scalar subquery, which raised an error if
        -- two directory objects ever carried the same SID.
        WITH owned AS (
            SELECT owner.object_guid AS owner_guid,
                   string_agg(DISTINCT CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                                            THEN 'AdminSDHolder' ELSE 'the domain root' END,
                              ' and '
                              ORDER BY CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                                            THEN 'AdminSDHolder' ELSE 'the domain root' END)
                       AS owned_list,
                   jsonb_agg(target.dn_current ORDER BY target.dn_current, target.object_guid)
                       AS object_dns
            FROM directory_object target
            JOIN directory_object owner
                ON owner.object_sid = target.owner_sid AND owner.client_id = target.client_id
               AND NOT owner.is_deleted
            WHERE target.client_id = %(client_id)s
              AND target.owner_sid IS NOT NULL
              AND (
                    target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = target.object_guid
                                 AND d.client_id = target.client_id AND d.valid_to IS NULL)
                  )
            GROUP BY owner.object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.3] A disabled owner is not usable until re-enabled: 'high'.
            CASE WHEN u.is_enabled IS FALSE THEN 'high' ELSE 'critical' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' owns ' || ow.owned_list
                || ' and is independently weak: ' || (
                    -- [v1.3] Ordered by an explicit ordinal. A disabled
                    -- account cannot authenticate, so it is labelled
                    -- 'disabled' rather than roastable/PASSWD_NOTREQD.
                    SELECT string_agg(x, ', ' ORDER BY ord) FROM (VALUES
                        (1, CASE WHEN u.is_enabled IS FALSE THEN 'disabled' END),
                        (2, CASE WHEN u.is_enabled IS NOT FALSE
                                  AND (u.last_logon_timestamp IS NULL OR u.last_logon_timestamp < now() - interval '90 days')
                              THEN 'dormant' END),
                        (3, CASE WHEN u.is_enabled IS NOT FALSE
                                  AND u.service_principal_names IS NOT NULL AND array_length(u.service_principal_names, 1) > 0
                              THEN 'Kerberoastable' END),
                        (4, CASE WHEN u.is_enabled IS NOT FALSE AND (u.user_account_control & 4194304) != 0
                              THEN 'AS-REP roastable' END),
                        (5, CASE WHEN u.is_enabled IS NOT FALSE AND (u.user_account_control & 32) != 0
                              THEN 'PASSWD_NOTREQD' END)
                    ) AS v(ord, x) WHERE x IS NOT NULL
                ) AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'is_enabled', u.is_enabled,
                'object_dns', ow.object_dns
            ) AS detail
        FROM owned ow
        JOIN ad_user u
            ON u.object_guid = ow.owner_guid
           AND u.client_id = %(client_id)s
           AND u.valid_to IS NULL
        WHERE (
                u.is_enabled IS FALSE
                OR u.last_logon_timestamp IS NULL OR u.last_logon_timestamp < now() - interval '90 days'
                OR (u.service_principal_names IS NOT NULL AND array_length(u.service_principal_names, 1) > 0)
                OR (u.user_account_control & 4194304) != 0
                OR (u.user_account_control & 32) != 0
              )
    """,
}
