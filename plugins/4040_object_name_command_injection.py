"""
Plugin 4040: Object Name Contains PowerShell Command-Injection Characters (CVE-2026-123387)

CVE-2026-123387 (Active Directory Domain Services elevation of privilege,
CVSS 8.0, November 2026): "An authenticated attacker with delegated
directory permissions can rename an object using crafted characters. A
privileged administrator must then generate and run the affected PowerShell
remediation script." The name is pasted into the generated script, so a
name that closes the script's quoting and appends a command runs that
command as the administrator. Microsoft does not name the script, and its
presence is not visible in the directory; the crafted name is. This check
finds names that carry such a payload, whether or not the script is ever
run -- an object renamed this way is an attack in progress or a test of one.

Values checked: each object's own RDN (text before the first unescaped
comma of its distinguished name, the escaping removed), its
sAMAccountName and, for users, its userPrincipalName.

Indicators:
  * 'subexpression': $( or ${ (PowerShell runs what is inside, even in a
    double-quoted string);
  * 'quote_then_separator': a quote character (straight or typographic --
    PowerShell treats U+2018-U+201E as quotes) followed by ;, | or & --
    the shape of a payload that leaves the script's string;
  * 'separator_then_command': ;, | or & followed by a command (iex, iwr,
    irm, powershell, pwsh, cmd, or a Verb-Noun cmdlet with a common verb);
  * 'backtick': the PowerShell escape character;
  * 'line_break': a carriage return or line feed (literal, or escaped
    \\0A / \\0D in the distinguished name), which starts a new statement.

One finding per object, status 'warn':
  * high: any of subexpression, quote_then_separator,
    separator_then_command (payload shape);
  * medium: only a backtick or a line break.
Ordinary punctuation on its own (an apostrophe in O'Brien, & in R&D) is not
reported.

Data: directory_object, ad_user. Identity = the object. Related: 4027
(hidden Unicode characters in names), 11008 (name attributes modified
recently, from replication metadata: who renamed it and when).
"""

PLUGIN = {
    "plugin_id": 4040,
    "category": "Domain",
    "name": "Object Name Contains PowerShell Command-Injection Characters (CVE-2026-123387)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "HYGIENE-4040",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-SI-10",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "SOC2-CC7.2",
        "MITRE-ATTCK-T1059.001",
        "MITRE-ATTCK-T1068",
        "CVE-2026-123387",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-123387 (Active Directory Domain Services Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-123387"},
        {"title": "Microsoft: about_Quoting_Rules (PowerShell)",
         "url": "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules"},
        {"title": "MITRE ATT&CK T1059.001: Command and Scripting Interpreter: PowerShell",
         "url": "https://attack.mitre.org/techniques/T1059/001/"},
    ],
    "description": (
        "An object's name (RDN, sAMAccountName or userPrincipalName) contains characters that "
        "inject PowerShell commands when the name is pasted into a script: a $( ) subexpression, a "
        "quote followed by a command separator, a separator followed by a command, a backtick or a "
        "line break. CVE-2026-123387 (November 2026, CVSS 8.0) is exploited this way: a delegated "
        "user renames an object, and a Microsoft-generated remediation script run later by an "
        "administrator executes the name. High for a payload-shaped name; medium for a lone "
        "backtick or line break."
    ),
    "remediation": (
        "Install the November 2026 security update on the domain controllers and on the "
        "administrators' management hosts. Do not generate or run remediation scripts until the "
        "names listed here are cleaned up. Find who renamed each object and when (plugin 11008, "
        "the domain controllers' event 5136 / 4781, or repadmin /showobjmeta), treat that account "
        "as compromised until shown otherwise, rename the object to a plain name, and review what "
        "the account's delegated rights allow it to rename (remove rights it does not need)."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        target AS (
            SELECT o.object_guid, o.object_class, o.dn_current, o.sam_account_name AS obj_label,
                   'sAMAccountName'::text AS attribute, o.sam_account_name AS raw_val
              FROM directory_object o
             WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
               AND o.sam_account_name IS NOT NULL
            UNION ALL
            SELECT o.object_guid, o.object_class, o.dn_current, o.sam_account_name,
                   'RDN', substring(o.dn_current from '^(([^,\\]|\\.)*)')
              FROM directory_object o
             WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
            UNION ALL
            SELECT o.object_guid, o.object_class, o.dn_current, o.sam_account_name,
                   'userPrincipalName', u.user_principal_name
              FROM ad_user u
              JOIN directory_object o
                ON o.object_guid = u.object_guid AND o.client_id = u.client_id AND NOT o.is_deleted
             WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
               AND u.user_principal_name IS NOT NULL
        ),
        -- Cheap pre-filter: only values holding one of the characters
        -- involved are examined further.
        flagged AS (
            SELECT t.*,
                   CASE WHEN t.attribute = 'RDN'
                        THEN regexp_replace(
                                 regexp_replace(regexp_replace(t.raw_val, '^[A-Za-z0-9-]+=', ''),
                                                '\\0[AaDd]', E'\n', 'g'),
                                 '\\(.)', '\1', 'g')
                        ELSE t.raw_val END AS val
              FROM target t
             WHERE t.raw_val ~ '[$`;|&\r\n]' OR t.raw_val ~ '\\0[AaDd]'
        ),
        ind AS (
            SELECT f.*,
                   ARRAY_REMOVE(ARRAY[
                       CASE WHEN f.val ~ '\$[({]' THEN 'subexpression' END,
                       CASE WHEN f.val ~ '["''‘’‚‛“”„‟]\s*[;|&]' THEN 'quote_then_separator' END,
                       CASE WHEN f.val ~* '[;|&]\s*(iex|iwr|irm|powershell|pwsh|cmd|(invoke|start|remove|set|add|new|stop|enable|disable|import|out|write|get)-[a-z]+)\M'
                            THEN 'separator_then_command' END,
                       CASE WHEN strpos(f.val, '`') > 0 THEN 'backtick' END,
                       CASE WHEN f.val ~ '[\r\n]' THEN 'line_break' END
                   ], NULL) AS indicators
              FROM flagged f
        ),
        hit AS (
            SELECT * FROM ind WHERE cardinality(indicators) > 0
        ),
        agg AS (
            SELECT h.object_guid,
                   min(h.object_class::text) AS object_class,
                   min(h.dn_current) AS dn_current,
                   min(h.obj_label) AS obj_label,
                   bool_or(h.indicators && ARRAY['subexpression', 'quote_then_separator',
                                                 'separator_then_command']) AS payload,
                   jsonb_agg(jsonb_build_object(
                       'attribute', h.attribute,
                       'value', regexp_replace(h.val, '[\r\n]', '<LF>', 'g'),
                       'indicators', to_jsonb(h.indicators))
                       ORDER BY h.attribute) AS occurrences,
                   string_agg(DISTINCT h.attribute, ', ') AS attr_text,
                   (SELECT string_agg(DISTINCT i, ', ')
                      FROM hit h2, unnest(h2.indicators) AS i
                     WHERE h2.object_guid = h.object_guid) AS ind_text
              FROM hit h
             GROUP BY h.object_guid
        )
        SELECT
            'warn' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.payload THEN 'high' ELSE 'medium' END AS fd_severity,
            'Object "' || COALESCE(a.obj_label, a.dn_current) || '": its '
                || a.attr_text || ' contains PowerShell command-injection characters ('
                || a.ind_text || '), the technique of CVE-2026-123387: find who renamed it and '
                || 'clean it up before running any generated remediation script' AS summary,
            jsonb_build_object(
                'object_label', a.obj_label,
                'distinguished_name', a.dn_current,
                'object_class', a.object_class,
                'payload_shape', a.payload,
                'occurrences', a.occurrences,
                'cve', 'CVE-2026-123387',
                'related_plugins', jsonb_build_array(4027, 11008)
            ) AS detail
        FROM agg a
    """,
}
