"""
Plugin 2012: Computer Account Description/Notes Field May Contain Password Material

Same technique as user-account plugin 1021, applied to computer objects.
Local admin passwords, BIOS passwords, or other machine-specific
credentials left in a computer's description/notes field are just as
readable by any authenticated domain user as the equivalent finding on a
user account.

[v1.4] Keyword match tightened and broadened at once: the bare
ILIKE '%pass%' matched "passive", "bypass", "compass", "passthrough"
("Passive node", "SCOM pass-through"), while "pw:", "cred=", "Kennwort"
and "contrasena" were missed. Now a word-boundary regex (pass as a word but not "pass-through",
password/passwd/passphrase, pwd, pw: / pw=, cred(s)/credential(s) followed
by : or =, and common German/Spanish/French/Dutch terms). The detail no
longer copies the full description/notes text into the evidence store --
a real password would be replicated into reports -- but records which
field matched, the matched keyword and the field length.
"""

PLUGIN = {
    "plugin_id": 2012,
    "category": "Computer Accounts",
    "name": "Computer Account Description/Notes Field May Contain Password Material",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the sensitive text from the field immediately, and treat "
        "the exposed credential as compromised -- rotate the local admin "
        "password (or whatever credential was exposed) on this machine "
        "specifically, and check whether the same password was reused on "
        "any other machine, which is common when a credential like this "
        "gets documented once and copied elsewhere."
    ),
    "control_id": "CRED-106",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1552.001"],
    "references": [],
    "description": (
        "The description and info (\"Notes\" in ADUC) attributes are free "
        "text, readable by any authenticated domain user via a plain "
        "LDAP query. On computer objects specifically, this is a common "
        "place for admins to leave a machine's local administrator "
        "password, a BIOS/firmware password, or other machine-specific "
        "credential material -- the same underlying exposure pattern as "
        "user-account plugin 1021, just as damaging here since a local "
        "admin password directly enables lateral movement onto that "
        "machine. Matched by a word-boundary keyword regex (pass, "
        "password, passwd, passphrase, pwd, pw: / pw=, cred(s)/"
        "credential(s) followed by : or =, Passwort, Kennwort, "
        "contrasena, mot de passe, wachtwoord), so words such as "
        "\"passive\" or \"bypass\" do not match. The field text itself is "
        "not copied into the finding; open the object in AD to review it. "
        "NOT downgraded when disabled: the readable password value doesn't disappear when this account is disabled."
    ),
    "base_severity": "high",
    "query": """
        WITH pat AS (
            SELECT '\\mpass(?![- ]?through)\\M|password|passwd|passphrase|passwort|kennwort|contrase|mot de passe|wachtwoord'
                   || '|\\mpwd\\M|\\mpw\\s*[:=]|\\mcred(ential)?s?\\s*[:=]' AS re
        ),
        hit AS (
            SELECT c.*,
                   c.description ~* p.re AS in_description,
                   c.notes ~* p.re AS in_notes,
                   lower(substring(c.description FROM '(?i)(' || p.re || ')')) AS description_keyword,
                   lower(substring(c.notes FROM '(?i)(' || p.re || ')')) AS notes_keyword
            FROM ad_computer c
            CROSS JOIN pat p
            WHERE c.valid_to IS NULL
              AND c.client_id = %(client_id)s
              AND (c.description ~* p.re OR c.notes ~* p.re)
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' has a description/notes field that may contain a password' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'matched_in_description', COALESCE(c.in_description, false),
                'matched_in_notes', COALESCE(c.in_notes, false),
                'description_keyword', c.description_keyword,
                'notes_keyword', c.notes_keyword,
                'description_length', length(c.description),
                'notes_length', length(c.notes),
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM hit c
    """,
}
