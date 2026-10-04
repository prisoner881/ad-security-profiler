"""
Plugin 3002: Group Description/Notes Field May Contain Password Material

Same technique as user-account plugin 1021 and computer-account plugin
2012, applied to group objects. Shared/service credentials, distribution
list access codes, or shared account passwords are a plausible thing to
find documented on a group's description specifically (e.g. a group
gating access to a shared mailbox or shared account).

[v1.1] Corrected against a real false-positive found in production: a
bare "pass"/"pwd" substring match also matches ordinary prose that
happens to mention passwords (e.g. several built-in groups' own
Microsoft-authored default descriptions explain password-replication
functionality in plain English). Tightened to require a colon-delimited
"label: value" structure -- exactly the pattern this project's own real
test data has consistently used for genuine leaked credentials -- rather
than a bare keyword match. Also excludes the two built-in RODC password
replication groups by RID (571, 572) as a direct, additional safeguard,
since their default descriptions are Microsoft-authored prose about
password replication policy, not admin-entered notes.

[v1.4] Keyword matching now uses whole words (\\m...\\M) from an explicit
list -- pass, password, passwd, passphrase, passcode, pwd, pw, and the
common localized forms kennwort / mot de passe / contrasena -- followed
by ":" or "=" and a non-empty value. This catches "pw:", "pwd=",
"password = x" and "Kennwort: x" (previously missed) and stops matching
words that merely start with "pass" ("passport:", "passive:",
"passthrough:") or a label with nothing after it.
"""

PLUGIN = {
    "plugin_id": 3002,
    "category": "Groups",
    "name": "Group Description/Notes Field May Contain Password Material",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the sensitive text from the field immediately, and treat "
        "the exposed credential as compromised -- rotate it, and check "
        "whether the same password is reused anywhere else. Group "
        "description fields are commonly used to document what a group "
        "gates access to, which makes them a plausible (and, once "
        "exposed, obviously readable by anyone) place to find a shared "
        "account or shared mailbox password."
    ),
    "control_id": "CRED-201",
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
        "plain LDAP query. Same underlying exposure pattern as plugins "
        "1021 and 2012, applied to group objects -- groups are a "
        "plausible place to find this specifically, since a group's "
        "description commonly documents what it gates access to (a "
        "shared mailbox, a shared service account), making it a "
        "natural, if careless, place for someone to also leave the "
        "credential itself. Requires a \"label: value\" or "
        "\"label=value\" structure after a whole-word password keyword "
        "(e.g. \"pass:\", \"password=\", \"pwd:\", \"pw:\", "
        "\"Kennwort:\") with a non-empty value, rather than a bare "
        "keyword match -- this is "
        "deliberately tighter than the equivalent user/computer plugins, "
        "since group descriptions (unlike typical user/computer "
        "descriptions) commonly include legitimate Microsoft-authored "
        "prose that discusses password-related functionality without "
        "containing an actual credential."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.is_protected_group THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN g.is_protected_group THEN 'Privileged ' ELSE '' END)
                || 'Group ' || COALESCE(g.sam_account_name, g.object_guid::text)
                || ' has a description/notes field that may contain a password' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'description', g.description,
                'notes', g.notes,
                'is_protected_group', g.is_protected_group
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND NOT (COALESCE(do2.object_sid, '') LIKE '%%-571' OR COALESCE(do2.object_sid, '') LIKE '%%-572')
          AND (
                g.description ~* '\\m(pass|password|passwd|passwort|passphrase|passcode|pwd|pw|kennwort|mot de passe|contrase(n|ñ)a)\\M\\s*[:=]\\s*[^\\s]'
                OR g.notes ~* '\\m(pass|password|passwd|passwort|passphrase|passcode|pwd|pw|kennwort|mot de passe|contrase(n|ñ)a)\\M\\s*[:=]\\s*[^\\s]'
              )
    """,
}
