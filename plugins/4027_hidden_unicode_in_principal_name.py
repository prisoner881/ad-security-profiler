"""
Plugin 4027: Hidden Unicode Characters in a Principal Name

Detects invisible, formatting and bidirectional-control Unicode characters
embedded in sAMAccountName, distinguishedName, userPrincipalName and
servicePrincipalName values.

These characters have no legitimate place in a principal name. Their purpose
is to make two directory objects render identically in dsa.msc, ADUC and most
reporting tools while remaining distinct to the directory itself. Yossi Sassi
originally presented this as an Active Directory persistence technique -- an
account that looks exactly like a legitimate one, confusing responders and
delaying an investigation. Semperis' 2026 research then showed it is also the
mechanism behind two privilege escalation vulnerabilities:

  * KerberLoss (CVE-2026-25177) -- bypasses SPN and SPN alias uniqueness
    verification, enabling duplicate and shadowing SPNs. See plugins 4028
    and 4029 for the resulting conditions.
  * ResetNightmare (CVE-2026-27912) -- bypasses UPN uniqueness verification.
    See plugin 1043.

Why this plugin can exist at all
--------------------------------
Semperis concluded that reliable detection over LDAP is not possible. Of 385
invisible characters they tested, only 106 could be filtered for; the domain
controller treats some as whitespace and ignores others entirely, so an LDAP
filter for a "normal" value silently also matches the poisoned one. Their
recommended detection is SACL auditing and Security event 5136 instead.

That limitation is a property of the LDAP server's string comparison, not of
the data. adprofiler.py has already extracted these values out of LDAP and
stored them as text in PostgreSQL, where they can be inspected byte by byte.
This plugin therefore detects reliably what an LDAP query cannot -- a direct
consequence of the collect-then-analyse split, and worth remembering when
similar "undetectable" findings come up.

Two severity classes
--------------------
Zero-width, formatting, bidirectional-control and filler characters are
reported at high severity: there is no benign reason for them in a principal
name. Unusual whitespace (non-breaking space and the typographic space
variants) is reported at medium, because it does occasionally arrive
innocently by copy-paste from a document, though it is still wrong.

Deliberately not flagged: accented Latin, CJK, Cyrillic, apostrophes and
hyphens. These are ordinary characters in real names and the plugin must not
punish organisations for having non-English users. Verified against
representative samples during development.

Scope note
----------
The character list below is a well-established starting set, not the complete
385 Semperis enumerated. It should be validated against a live directory
before being treated as exhaustive, since the domain controller's handling
varies by character and by attribute. A finding here is reliable; an absence
of findings is good evidence but not proof.

[v1.1] Four corrections. (1) The distinguishedName branch now tests
only the object's own RDN, not the full DN: v1.0 reported every
descendant of an OU/container with an odd character in its name as
well. (2) "critical" now requires an invisible (non-whitespace)
character inside a UPN or SPN itself; v1.0 combined an invisible
character anywhere (e.g. the DN) with a mere no-break space in the UPN.
(3) U+200C ZWNJ, U+200E LRM, U+200F RLM and U+061C ALM are ordinary
orthographic marks in Persian, Kurdish, Hebrew and Arabic text; when
they occur in a value that contains Hebrew/Arabic-script letters, or
only in the RDN, they are reported at medium (class "script_mark")
rather than high. (4) The code-point list now also covers U+034F
COMBINING GRAPHEME JOINER, U+17B4/17B5 Khmer inherent vowels, variation
selectors U+FE00-FE0F and U+E0100-E01EF, tag characters U+E0000-E007F
and musical-symbol formatting characters U+1D173-1D17A; the regex
character classes are now generated from the single code-point table so
they cannot drift apart. Computer (and gMSA) userPrincipalName values,
collected since schema v36, are checked too.
"""

PLUGIN = {
    "plugin_id": 4027,
    "category": "Domain",
    "name": "Hidden Unicode Characters in a Principal Name",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat any high-severity hit as suspicious until explained. An "
        "invisible character in a logon name, distinguished name, UPN or SPN "
        "is not something an administrator types by accident, and the object "
        "will look completely normal in native tooling -- so do not dismiss "
        "it on the basis that the name 'looks fine'. "
        "Start by identifying whether a near-twin exists: search for another "
        "object whose name matches once the hidden characters are stripped. "
        "The evidence for each finding includes a rendered form with the "
        "hidden characters marked, and the code points with their offsets, "
        "which is enough to construct that comparison. A matching pair is "
        "the signature of the impersonation technique; a lone object may be "
        "migration debris or a bad copy-paste. "
        "Where a twin exists, or where the affected attribute is a UPN or an "
        "SPN, escalate: check plugin 1043 for UPN impersonation, and plugins "
        "4028 and 4029 for duplicate or shadowing SPNs, since those are the "
        "conditions this technique is used to create. Determine who created "
        "or last modified the object, then disable rather than delete it "
        "while the investigation runs, so the evidence survives. "
        "To remediate a benign case, rewrite the attribute with the hidden "
        "characters removed; they cannot be edited out reliably in a GUI "
        "because they are not visible, so set the value explicitly with "
        "Set-ADUser, Set-ADComputer or setspn as appropriate. "
        "Preventively, confirm uniqueness verification is enforced (plugin "
        "4030) and that domain controllers carry the March and April 2026 "
        "updates. Enable SACL auditing on sAMAccountName, userPrincipalName "
        "and servicePrincipalName so event 5136 records future changes."
    ),
    "control_id": "ANOM-106",
    "framework_tags": ["MITRE-ATTCK-T1036", "MITRE-ATTCK-T1078.002",
                       "MITRE-ATTCK-T1098", "CVE-2026-25177", "CVE-2026-27912"],
    "references": [
        {"title": "Semperis: KerberLoss and ResetNightmare -- Kerberos downgrade and full domain takeover",
         "url": "https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/"},
        {"title": "MITRE ATT&CK T1036: Masquerading",
         "url": "https://attack.mitre.org/techniques/T1036/"},
    ],
    "description": (
        "Reports Active Directory objects whose sAMAccountName, "
        "distinguishedName, userPrincipalName or servicePrincipalName "
        "contains invisible Unicode -- zero-width characters, bidirectional "
        "controls, formatting characters or filler characters. These make an "
        "object render identically to a legitimate one in management tools "
        "while remaining distinct to the directory, and they are the "
        "mechanism by which KerberLoss (CVE-2026-25177) and ResetNightmare "
        "(CVE-2026-27912) bypass principal-name uniqueness verification. "
        "Detection is performed against the collected values in the database "
        "rather than over LDAP, because the domain controller's own string "
        "comparison ignores many of these characters and cannot filter for "
        "them reliably. Unusual whitespace, and directional/joiner marks "
        "that occur in genuine right-to-left or Persian-script names, are "
        "reported separately at lower severity. Only the object's own RDN "
        "is examined for distinguishedName. Accented, CJK and other "
        "legitimate non-ASCII name characters are not flagged."
    ),
    "base_severity": "high",
    "query": """
        WITH cp_single (code, cp_name, cp_class) AS (
            VALUES
            -- Zero-width and formatting characters: no legitimate use.
            (   173, 'U+00AD SOFT HYPHEN',                    'invisible'),
            (  1564, 'U+061C ARABIC LETTER MARK',             'invisible'),
            (  6158, 'U+180E MONGOLIAN VOWEL SEPARATOR',      'invisible'),
            (  8203, 'U+200B ZERO WIDTH SPACE',               'invisible'),
            (  8204, 'U+200C ZERO WIDTH NON-JOINER',          'invisible'),
            (  8205, 'U+200D ZERO WIDTH JOINER',              'invisible'),
            (  8288, 'U+2060 WORD JOINER',                    'invisible'),
            (  8289, 'U+2061 FUNCTION APPLICATION',           'invisible'),
            (  8290, 'U+2062 INVISIBLE TIMES',                'invisible'),
            (  8291, 'U+2063 INVISIBLE SEPARATOR',            'invisible'),
            (  8292, 'U+2064 INVISIBLE PLUS',                 'invisible'),
            ( 65279, 'U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)','invisible'),
            ( 65529, 'U+FFF9 INTERLINEAR ANNOTATION ANCHOR',  'invisible'),
            ( 65530, 'U+FFFA INTERLINEAR ANNOTATION SEPARATOR','invisible'),
            ( 65531, 'U+FFFB INTERLINEAR ANNOTATION TERMINATOR','invisible'),
            -- Bidirectional controls: can visually reorder a name.
            (  8206, 'U+200E LEFT-TO-RIGHT MARK',             'bidi_control'),
            (  8207, 'U+200F RIGHT-TO-LEFT MARK',             'bidi_control'),
            (  8234, 'U+202A LEFT-TO-RIGHT EMBEDDING',        'bidi_control'),
            (  8235, 'U+202B RIGHT-TO-LEFT EMBEDDING',        'bidi_control'),
            (  8236, 'U+202C POP DIRECTIONAL FORMATTING',     'bidi_control'),
            (  8237, 'U+202D LEFT-TO-RIGHT OVERRIDE',         'bidi_control'),
            (  8238, 'U+202E RIGHT-TO-LEFT OVERRIDE',         'bidi_control'),
            (  8294, 'U+2066 LEFT-TO-RIGHT ISOLATE',          'bidi_control'),
            (  8295, 'U+2067 RIGHT-TO-LEFT ISOLATE',          'bidi_control'),
            (  8296, 'U+2068 FIRST STRONG ISOLATE',           'bidi_control'),
            (  8297, 'U+2069 POP DIRECTIONAL ISOLATE',        'bidi_control'),
            -- Filler characters that render as nothing.
            (  4447, 'U+115F HANGUL CHOSEONG FILLER',         'filler'),
            (  4448, 'U+1160 HANGUL JUNGSEONG FILLER',        'filler'),
            ( 12644, 'U+3164 HANGUL FILLER',                  'filler'),
            ( 65440, 'U+FFA0 HALFWIDTH HANGUL FILLER',        'filler'),
            -- Line and paragraph separators.
            (  8232, 'U+2028 LINE SEPARATOR',                 'invisible'),
            (  8233, 'U+2029 PARAGRAPH SEPARATOR',            'invisible'),
            -- Unusual whitespace: lower severity, occasionally innocent.
            (   160, 'U+00A0 NO-BREAK SPACE',                 'odd_space'),
            (  8192, 'U+2000 EN QUAD',                        'odd_space'),
            (  8193, 'U+2001 EM QUAD',                        'odd_space'),
            (  8194, 'U+2002 EN SPACE',                       'odd_space'),
            (  8195, 'U+2003 EM SPACE',                       'odd_space'),
            (  8196, 'U+2004 THREE-PER-EM SPACE',             'odd_space'),
            (  8197, 'U+2005 FOUR-PER-EM SPACE',              'odd_space'),
            (  8198, 'U+2006 SIX-PER-EM SPACE',               'odd_space'),
            (  8199, 'U+2007 FIGURE SPACE',                   'odd_space'),
            (  8200, 'U+2008 PUNCTUATION SPACE',              'odd_space'),
            (  8201, 'U+2009 THIN SPACE',                     'odd_space'),
            (  8202, 'U+200A HAIR SPACE',                     'odd_space'),
            (  8239, 'U+202F NARROW NO-BREAK SPACE',          'odd_space'),
            (  8287, 'U+205F MEDIUM MATHEMATICAL SPACE',      'odd_space'),
            ( 12288, 'U+3000 IDEOGRAPHIC SPACE',              'odd_space'),
            -- [v1.1] Further invisible / default-ignorable characters.
            (   847, 'U+034F COMBINING GRAPHEME JOINER',      'invisible'),
            (  6068, 'U+17B4 KHMER VOWEL INHERENT AQ',        'invisible'),
            (  6069, 'U+17B5 KHMER VOWEL INHERENT AA',        'invisible')
        ),
        -- [v1.1] Ranges: variation selectors, tag characters and the
        -- musical-symbol formatting characters.
        cp AS (
            SELECT * FROM cp_single
            UNION ALL
            SELECT g, 'U+' || upper(to_hex(g)) || ' VARIATION SELECTOR', 'invisible'
            FROM generate_series(65024, 65039) g
            UNION ALL
            SELECT g, 'U+' || upper(to_hex(g)) || ' VARIATION SELECTOR SUPPLEMENT', 'invisible'
            FROM generate_series(917760, 917999) g
            UNION ALL
            SELECT g, 'U+' || upper(to_hex(g)) || ' TAG CHARACTER', 'invisible'
            FROM generate_series(917504, 917631) g
            UNION ALL
            SELECT g, 'U+' || upper(to_hex(g)) || ' MUSICAL SYMBOL FORMATTING', 'invisible'
            FROM generate_series(119155, 119162) g
        ),
        -- [v1.1] Character classes generated from the table (none of the
        -- listed characters is special inside a bracket expression).
        pat AS (
            SELECT '[' || string_agg(chr(code), '') || ']' AS any_cp,
                   '[' || string_agg(chr(code), '') FILTER (WHERE cp_class <> 'odd_space') || ']' AS strip_cp
            FROM cp
        ),
        target AS (
            SELECT do2.object_guid, do2.object_class, do2.dn_current,
                   do2.sam_account_name AS obj_label,
                   'sAMAccountName'::text AS attribute,
                   do2.sam_account_name AS val
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND NOT do2.is_deleted
              AND do2.sam_account_name IS NOT NULL
            UNION ALL
            -- [v1.1] Own RDN only (text before the first unescaped comma),
            -- so a character in a parent OU is not reported on every child.
            SELECT do2.object_guid, do2.object_class, do2.dn_current,
                   do2.sam_account_name, 'distinguishedName',
                   substring(do2.dn_current from '^(([^,\\\\]|\\\\.)*)')
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND NOT do2.is_deleted
            UNION ALL
            SELECT do2.object_guid, do2.object_class, do2.dn_current,
                   do2.sam_account_name, 'userPrincipalName', u.user_principal_name
            FROM ad_user u
            JOIN directory_object do2
              ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
             AND NOT do2.is_deleted
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND u.user_principal_name IS NOT NULL
            UNION ALL
            -- [v1.1] computer / gMSA UPNs (collected since schema v36)
            SELECT do2.object_guid, do2.object_class, do2.dn_current,
                   do2.sam_account_name, 'userPrincipalName', c.user_principal_name
            FROM ad_computer c
            JOIN directory_object do2
              ON do2.object_guid = c.object_guid AND do2.client_id = c.client_id
             AND NOT do2.is_deleted
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND c.user_principal_name IS NOT NULL
            UNION ALL
            SELECT do2.object_guid, do2.object_class, do2.dn_current,
                   do2.sam_account_name, 'servicePrincipalName', se.spn
            FROM spn_edge se
            JOIN directory_object do2
              ON do2.object_guid = se.object_guid AND do2.client_id = se.client_id
             AND NOT do2.is_deleted
            WHERE se.client_id = %(client_id)s
              AND se.valid_to IS NULL
              AND se.spn IS NOT NULL
        ),
        -- Cheap pre-filter so the per-code-point breakdown only runs on the
        -- handful of values that actually contain something.
        flagged AS (
            SELECT t.* FROM target t
            WHERE t.val ~ (SELECT any_cp FROM pat)
        ),
        hit AS (
            SELECT f.object_guid, f.object_class, f.dn_current, f.obj_label,
                   f.attribute, f.val, cp.code, cp.cp_name,
                   -- [v1.1] ZWNJ / LRM / RLM / ALM are orthographic marks in
                   -- Hebrew, Arabic and Persian-script text: medium when the
                   -- value contains such letters, or when only in the RDN.
                   CASE
                       WHEN cp.code IN (1564, 8204, 8206, 8207)
                        AND (f.attribute = 'distinguishedName'
                             OR f.val ~ U&'[\\0590-\\08FF\\FB1D-\\FDFF\\FE70-\\FEFC]')
                       THEN 'script_mark'
                       ELSE cp.cp_class
                   END AS cp_class,
                   strpos(f.val, chr(cp.code)) AS char_offset
            FROM flagged f
            JOIN cp ON strpos(f.val, chr(cp.code)) > 0
        ),
        agg AS (
            SELECT object_guid,
                   min(object_class::text) AS object_class,
                   min(dn_current) AS dn_current,
                   min(obj_label) AS obj_label,
                   bool_or(cp_class NOT IN ('odd_space', 'script_mark')) AS has_invisible,
                   bool_or(cp_class = 'script_mark') AS has_script_mark,
                   -- [v1.1] per-hit: an invisible character IN a UPN/SPN
                   bool_or(cp_class NOT IN ('odd_space', 'script_mark')
                           AND attribute IN ('userPrincipalName',
                                             'servicePrincipalName')) AS affects_auth_name,
                   count(*) AS hit_count,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'attribute', attribute,
                       'code_point', cp_name,
                       'class', cp_class,
                       'offset', char_offset,
                       'rendered',
                           regexp_replace(val, (SELECT any_cp FROM pat), '<?>', 'g'),
                       'stripped',
                           regexp_replace(val, (SELECT strip_cp FROM pat), '', 'g')
                   )) AS occurrences
            FROM hit
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN a.affects_auth_name THEN 'critical'
                WHEN a.has_invisible THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            CASE WHEN a.has_invisible
                 THEN 'Object "' || COALESCE(a.obj_label, a.dn_current)
                      || '" contains invisible Unicode characters in '
                 WHEN a.has_script_mark
                 THEN 'Object "' || COALESCE(a.obj_label, a.dn_current)
                      || '" contains directional or joiner marks (common in right-to-left or Persian-script names) in '
                 ELSE 'Object "' || COALESCE(a.obj_label, a.dn_current)
                      || '" contains unusual whitespace characters in '
            END
                || (SELECT string_agg(DISTINCT o.value ->> 'attribute', ', ')
                    FROM jsonb_array_elements(a.occurrences) AS o)
                || ' -- the name renders identically to a legitimate one in '
                   'native tooling'
                || CASE WHEN a.affects_auth_name
                        THEN ', and an authentication name is affected '
                             '(see CVE-2026-25177 / CVE-2026-27912)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'object_label', a.obj_label,
                'distinguished_name', a.dn_current,
                'object_class', a.object_class,
                'contains_invisible_characters', a.has_invisible,
                'contains_script_marks', a.has_script_mark,
                'affects_authentication_name', a.affects_auth_name,
                'occurrence_count', a.hit_count,
                'occurrences', a.occurrences,
                'detection_note',
                    'Detected against stored values, not via LDAP: the domain '
                    'controller ignores many of these characters in its own '
                    'string comparison and cannot filter for them reliably',
                'related_plugins', jsonb_build_array(1043, 4028, 4029, 4030),
                'corroborating_event_id', 5136
            ) AS detail
        FROM agg a
    """,
}
