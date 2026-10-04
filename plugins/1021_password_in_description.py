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

[v1.7] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.8] Matching and severity tuned against both kinds of noise:
- More terms: standalone "pw", "pass" followed by digits (pass123), and
  common non-English words (Passwort, Kennwort, mot de passe,
  contraseña, senha, wachtwoord, parola, hasło, lösenord,
  adgangskode, salasana).
- Benign administrative phrases are removed before matching: "password
  never/does not expire(s)" and "password reset/changed by <who>" -- the
  usual service-account and helpdesk annotations.
- Severity: a term followed by an assignment (":", "=", " is ", " to ")
  -- e.g. "temp pass: X", "pwd reset to X" -- is high (critical when
  privileged or Tier 0/1) as before; a bare mention is now medium (high
  when privileged or Tier 0/1).
- detail no longer copies the value verbatim: the text following an
  assignment is masked (********), so the evidence store does not spread
  the password further. Summary wording unchanged.
"""

PLUGIN = {
    "plugin_id": 1021,
    "category": "User Accounts",
    "name": "Account Description/Notes Field May Contain Password Material",
    "version": "1.8",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1552.001",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "The description and info (\"Notes\" in ADUC) attributes are "
        "free text, readable by any authenticated domain user via a "
        "plain LDAP query -- no elevated rights needed. A well-documented, "
        "extremely common real-world finding is admins leaving passwords "
        "or credential hints here during onboarding or password resets "
        "(e.g. \"temp pass: Summer2026!\"). Detection here is a "
        "word-boundary match against the standalone words 'pass'/'pwd'/"
        "'pw' (and 'pass' followed by digits), against 'password'/"
        "'passwd'/'passphrase', and against common non-English terms "
        "(Passwort, Kennwort, mot de passe, contrase\u00f1a, senha, "
        "wachtwoord, ...) -- not a bare "
        "substring match, which would incorrectly flag ordinary words "
        "like Compass, Passport, or bypass that merely contain 'pass' "
        "as part of a longer word. A match should be treated as a probable "
        "credential exposure requiring rotation, not a formatting issue "
        "to quietly clean up. Benign annotations ('password never "
        "expires', 'password reset by helpdesk') are ignored. A term "
        "followed by a value assignment (':', '=', ' is ', ' to ') is high "
        "(critical for privileged/Tier 0-1 accounts); a bare mention is "
        "medium (high when privileged). The value after an assignment is "
        "masked in the stored detail. NOT downgraded when the account is "
        "disabled: the readable password value doesn't disappear when "
        "this account is disabled, and if the same human reused that "
        "password elsewhere (a very common pattern), that exposure is "
        "entirely unaffected by this account's state."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_check AS (
            -- [v1.7] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        cleaned AS (
            -- [v1.8] strip benign administrative phrases before matching
            SELECT u.*,
                   regexp_replace(COALESCE(u.description, '') || E'\n' || COALESCE(u.notes, ''),
                       '(password|passwd|pwd)s?\\s+(never|does\\s+not|doesn''t|do\\s+not|don''t|will\\s+not|won''t)\\s+expire[sd]?'
                       '|(password|passwd|pwd)\\s+(was\\s+)?(reset|changed)\\s+by\\s+\\S+',
                       ' ', 'gi') AS text_clean
            FROM ad_user u
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
        ),
        matched AS (
            SELECT c.*,
                   -- a term followed by a value assignment: high
                   c.text_clean ~* ('(\\mpass\\M|password|passwd|passphrase|passwort|kennwort|\\mpwd\\M|\\mpw\\M'
                                    '|mot\\s+de\\s+passe|contrase(ñ|n)a|\\msenha\\M|wachtwoord|\\mparola\\M'
                                    '|\\mhas(ł|l)o\\M|l(ö|o)senord|adgangskode|salasana)'
                                    '(\\s+(re)?set|\\s+changed)?\\s*(:|=|\\s(is|to)\\s)') AS has_assignment
            FROM cleaned c
            WHERE c.text_clean ~* ('\\mpass\\M|\\mpass[0-9]|password|passwd|passphrase|passwort|kennwort'
                                   '|\\mpwd\\M|\\mpw\\M|mot\\s+de\\s+passe|contrase(ñ|n)a|\\msenha\\M'
                                   '|wachtwoord|\\mparola\\M|\\mhas(ł|l)o\\M|l(ö|o)senord|adgangskode|salasana')
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.8] assignment-like match: high/critical as before; bare
            -- mention: one level lower (medium/high).
            CASE GREATEST(
                CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 4 ELSE 3 END,
                CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 4 ELSE 3 END
            ) - (CASE WHEN u.has_assignment THEN 0 ELSE 1 END)
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                ELSE 'medium'
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
                -- [v1.8] values after an assignment are masked so the
                -- evidence store does not copy the password.
                'description', regexp_replace(u.description,
                    '((pass|password|passwd|passphrase|passwort|kennwort|pwd|pw|mot\\s+de\\s+passe|contrase(ñ|n)a|senha'
                    '|wachtwoord|parola|has(ł|l)o|l(ö|o)senord|adgangskode|salasana)(\\s+(re)?set|\\s+changed)?\\s*(:|=|\\s(is|to)\\s)\\s*)\\S+',
                    '\\1********', 'gi'),
                'notes', regexp_replace(u.notes,
                    '((pass|password|passwd|passphrase|passwort|kennwort|pwd|pw|mot\\s+de\\s+passe|contrase(ñ|n)a|senha'
                    '|wachtwoord|parola|has(ł|l)o|l(ö|o)senord|adgangskode|salasana)(\\s+(re)?set|\\s+changed)?\\s*(:|=|\\s(is|to)\\s)\\s*)\\S+',
                    '\\1********', 'gi'),
                'value_assignment_found', u.has_assignment,
                'admin_count', u.admin_count,
                'tier', oc.tier,
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM matched u
        LEFT JOIN object_classification oc
            ON oc.object_guid = u.object_guid AND oc.client_id = u.client_id
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
    """,
}
