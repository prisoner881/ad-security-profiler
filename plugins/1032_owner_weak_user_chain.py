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
"""

PLUGIN = {
    "plugin_id": 1032,
    "category": "User Accounts",
    "name": "Domain Root or AdminSDHolder Owned by an Independently Weak User Account",
    "version": "1.1",
    "revision_date": "2026-07-17",
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
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): WriteOwner edge",
         "url": "https://bloodhound.specterops.io/resources/edges/write-owner"},
    ],
    "description": (
        "Refines plugin 5006 (any unexpected owner of the domain root "
        "or AdminSDHolder) with a specific, higher-urgency angle: the "
        "owner is a user account that is ALSO independently exploitable "
        "via at least one of dormancy (90+ days since last logon, or "
        "never logged on), Kerberoasting, AS-REP roasting, or a blank/"
        "not-required password. An owner can always rewrite an object's "
        "ACL to grant themselves anything regardless of current "
        "explicit permissions, so an easily-compromised (or long-"
        "abandoned) owner is meaningfully worse than an unexpected but "
        "otherwise well-secured one."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' owns ' || (CASE WHEN target.dn_current ILIKE 'CN=AdminSDHolder,%%' THEN 'AdminSDHolder' ELSE 'the domain root' END)
                || ' and is independently weak: ' || (
                    SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN u.last_logon_timestamp IS NULL OR u.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END),
                        (CASE WHEN u.service_principal_names IS NOT NULL AND array_length(u.service_principal_names, 1) > 0
                              THEN 'Kerberoastable' END),
                        (CASE WHEN (u.user_account_control & 4194304) != 0 THEN 'AS-REP roastable' END),
                        (CASE WHEN (u.user_account_control & 32) != 0 THEN 'PASSWD_NOTREQD' END)
                    ) AS v(x) WHERE x IS NOT NULL
                ) AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'object_dn', target.dn_current
            ) AS detail
        FROM directory_object target
        JOIN ad_user u ON u.object_guid = (
            SELECT owner.object_guid FROM directory_object owner
            WHERE owner.object_sid = target.owner_sid AND owner.client_id = target.client_id
        ) AND u.valid_to IS NULL
        WHERE target.client_id = %(client_id)s
          AND target.owner_sid IS NOT NULL
          AND (
                target.dn_current ILIKE 'CN=AdminSDHolder,%%'
                OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = target.object_guid AND d.valid_to IS NULL)
              )
          AND (
                u.last_logon_timestamp IS NULL OR u.last_logon_timestamp < now() - interval '90 days'
                OR (u.service_principal_names IS NOT NULL AND array_length(u.service_principal_names, 1) > 0)
                OR (u.user_account_control & 4194304) != 0
                OR (u.user_account_control & 32) != 0
              )
    """,
}
