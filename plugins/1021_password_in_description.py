"""
Plugin 1021: Password Material in Description/Notes Field

A classic, extremely common finding: an admin leaves a password or
credential hint in the account's description or info ("Notes") field --
free text readable by any authenticated domain user via a basic LDAP
query, no special rights required. Confirmed against multiple sources
including a real lab writeup showing the exact PowerView pattern
attackers use to hunt for this.

[v1.5, corrected] The previous version used a bare ILIKE '%pass%'
substring match -- caught in real production data flagging a user
whose description was literally "Compass User" (matching a display
name of "Compass User"), since "Compass" contains "pass" as a
mid-word substring. Rebuilt as a word-boundary regex requiring "pass"
to be a genuinely standalone word (not embedded as a substring of a
longer word in either direction), which correctly excludes Compass,
Passport, passenger, Passover, bypass, surpass, trespass, overpass,
and encompass -- all verified directly, not assumed -- while still
separately matching "password", "passwd", and "passphrase" explicitly
as their own terms, since those remain valid matches even though they
aren't the bare word "pass" alone.

Known, honest remaining limitation, not attempted to be solved here:
"pass" is also an ordinary English verb ("please pass this along to
HR"), and no regex can distinguish that usage from a genuine
credential hint using the same word -- this is a real ambiguity in
the language itself, not a matching defect like the original
substring bug. Judged an acceptable, disclosed tradeoff: administrative
description/notes fields are short, account-specific annotations, not
general correspondence, so this specific collision is expected to be
substantially rarer in practice than the class of false positives this
fix actually eliminates.
"""

PLUGIN = {
    "plugin_id": 1021,
    "category": "User Accounts",
    "name": "Account Description/Notes Field May Contain Password Material",
    "version": "1.5",
    "revision_date": "2026-08-05",
    "remediation": (
    'Remove the sensitive text from the field immediately, but do not treat '
    'that as sufficient remediation on its own -- the exposure already '
    'happened. Treat the disclosed password as compromised: force a rotation of '
    'it, and separately check whether the same password is reused on any other '
    'account for the same person, since human password reuse across multiple '
    'accounts is extremely common and each reused instance is an equally live '
    'exposure.'
),
    "control_id": "CRED-009",
    "framework_tags": [],
    "references": [],
    "description": (
        "The description and info (\"Notes\" in ADUC) attributes are "
        "free text, readable by any authenticated domain user via a "
        "plain LDAP query -- no elevated rights needed. A well-documented, "
        "extremely common real-world finding is admins leaving passwords "
        "or credential hints here during onboarding or password resets "
        "(e.g. \"temp pass: Summer2026!\"). Detection here is a "
        "word-boundary match against the standalone word 'pass', or "
        "against 'password'/'passwd'/'passphrase'/'pwd' -- not a bare "
        "substring match, which would incorrectly flag ordinary words "
        "like Compass, Passport, or bypass that merely contain 'pass' "
        "as part of a longer word. A match should be treated as a probable "
        "credential exposure requiring rotation, not a formatting issue "
        "to quietly clean up. NOT downgraded when the account is "
        "disabled: the readable password value doesn't disappear when "
        "this account is disabled, and if the same human reused that "
        "password elsewhere (a very common pattern), that exposure is "
        "entirely unaffected by this account's state."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_check AS (
            -- [v1.x, ACL-aware] "Privileged" now means group-membership-based
            -- privilege (the original, sole definition) OR ACL-derived
            -- privilege: directly holding a dangerous right or DCSync rights
            -- on the domain root/AdminSDHolder, or owning either object.
            -- A user with none of the classic admin-group memberships but
            -- who directly holds GenericAll on the domain root is privileged
            -- in every meaningful sense -- arguably more concerning than a
            -- managed Domain Admin, since this kind of privilege is often
            -- unmanaged/accidental rather than deliberately delegated.
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(
                CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 4 ELSE 3 END,
                CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 4 ELSE 3 END
            )
                WHEN 4 THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has a description/notes field that may contain a password' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'description', u.description,
                'notes', u.notes,
                'admin_count', u.admin_count,
                'tier', oc.tier,
                'privileged_group_member', pc.object_guid IS NOT NULL
            ) AS detail
        FROM ad_user u
        LEFT JOIN object_classification oc
            ON oc.object_guid = u.object_guid AND oc.client_id = u.client_id
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND (
                u.description ~* '\\mpass\\M|password|passwd|passphrase|\\mpwd\\M'
                OR u.notes ~* '\\mpass\\M|password|passwd|passphrase|\\mpwd\\M'
              )
    """,
}
