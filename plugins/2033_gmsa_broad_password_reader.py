"""
Plugin 2033: gMSA Password Retrievable by an Overly Broad Principal

Group Managed Service Accounts are designed around a specific,
narrow-by-default security model: only the exact principals listed in
msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword)
can retrieve the gMSA's automatically-rotated, otherwise-unknown
password. Unlike this project's other "unexpected principal" ACL
findings, there's no universal well-known "expected" reader list for a
gMSA -- legitimate readers are specific to whatever individual
computers or service accounts actually run that particular service,
which varies completely from one gMSA to the next. What IS
universally, unambiguously wrong regardless of a specific gMSA's
purpose is finding one of a small number of deliberately broad,
built-in principals in that list: Domain Computers, Domain Users,
Authenticated Users, or Everyone. Any of these means every computer or
every user in the domain can retrieve this gMSA's password outright,
which defeats the entire point of a Group Managed Service Account's
controlled-access design -- functionally equivalent to just writing
the password down somewhere everyone can read it.

[v1.1] One row per gMSA. The query used to emit one row per broad
trustee while keying the finding on the gMSA's GUID, so a gMSA listing
two broad principals (e.g. Domain Computers and Authenticated Users)
produced duplicate identities and the whole plugin errored. Matching
principals are now aggregated: the summary lists them sorted (unchanged
wording when there is only one) and detail.broad_readers carries each
one. The broad set now also includes Domain Guests (-514), Anonymous
Logon (S-1-5-7), BUILTIN\\Users (S-1-5-32-545) and Pre-Windows 2000
Compatible Access (S-1-5-32-554); domain RIDs are matched only on
domain SIDs (S-1-5-21-...). A broad principal nested (at any depth,
via v_effective_group_membership) inside a group that is a listed
reader is reported too, as "<principal> (via <group>)". The ad_computer
join is client-scoped. A disabled gMSA cannot authenticate, so it is
reported as 'warn'/medium with "(account disabled)" instead of
'fail'/critical.
"""

PLUGIN = {
    "plugin_id": 2033,
    "category": "Computer Accounts",
    "name": "gMSA Password Retrievable by an Overly Broad Principal",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the broad principal from this gMSA's "
        "PrincipalsAllowedToRetrieveManagedPassword list (`Set-ADServiceAccount "
        "-Identity <name> -PrincipalsAllowedToRetrieveManagedPassword "
        "<specific computers/groups>`, replacing rather than appending). "
        "Replace it with the specific computer accounts (or a dedicated "
        "security group containing only those computers) that actually "
        "run the service this gMSA authenticates for -- not a broad, "
        "built-in group that includes every computer or user in the "
        "domain regardless of whether they have any legitimate reason "
        "to retrieve this specific password."
    ),
    "control_id": "GMSA-201",
    "framework_tags": [
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-800-53-AC-2",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "PCI-DSS-4.0-8.6.1",
        "PCI-DSS-4.0-8.6.3",
        "PCI-DSS-4.0-7.2.5",
        "CIS-CSC-8-3.11",
        "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1552",
    ],
    "references": [
        {"title": "The Hacker Recipes: ReadGMSAPassword",
         "url": "https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword"},
    ],
    "description": (
        "msDS-GroupMSAMembership (PrincipalsAllowedToRetrieveManagedPassword) "
        "controls who can retrieve a gMSA's automatically-rotated "
        "password. Unlike this project's other ACL findings, there's no "
        "universal expected-reader list -- legitimate readers vary "
        "completely by gMSA, depending on which specific computers/"
        "services actually use it. What's unambiguously wrong regardless "
        "of purpose: finding one of the deliberately broad, built-in "
        "principals (Domain Computers, Domain Users, Domain Guests, "
        "Authenticated Users, Everyone, Anonymous Logon, BUILTIN\\Users, "
        "Pre-Windows 2000 Compatible Access) in that list -- directly or "
        "nested in a listed group -- which means every computer or "
        "user in the domain can retrieve the password -- functionally "
        "equivalent to not protecting it at all."
    ),
    "base_severity": "critical",
    "query": """
        WITH broad AS (
            -- Broad principals by SID (never by name).
            SELECT sid, label FROM (VALUES
                ('S-1-1-0', 'Everyone'),
                ('S-1-5-7', 'Anonymous Logon'),
                ('S-1-5-11', 'Authenticated Users'),
                ('S-1-5-32-545', 'BUILTIN\\Users'),
                ('S-1-5-32-554', 'Pre-Windows 2000 Compatible Access')
            ) v(sid, label)
        ),
        readers AS (
            SELECT gr.gmsa_guid, gr.trustee_sid
            FROM gmsa_password_reader_edge gr
            WHERE gr.client_id = %(client_id)s
              AND gr.valid_to IS NULL
              AND gr.ace_type = 'allow'
        ),
        broad_match AS (
            -- A broad principal listed directly.
            SELECT r.gmsa_guid, r.trustee_sid,
                   CASE WHEN r.trustee_sid LIKE 'S-1-5-21-%%-513' THEN 'Domain Users'
                        WHEN r.trustee_sid LIKE 'S-1-5-21-%%-514' THEN 'Domain Guests'
                        WHEN r.trustee_sid LIKE 'S-1-5-21-%%-515' THEN 'Domain Computers'
                        ELSE b.label END AS label
            FROM readers r
            LEFT JOIN broad b ON b.sid = r.trustee_sid
            WHERE b.sid IS NOT NULL
               OR r.trustee_sid LIKE 'S-1-5-21-%%-513'
               OR r.trustee_sid LIKE 'S-1-5-21-%%-514'
               OR r.trustee_sid LIKE 'S-1-5-21-%%-515'
            UNION
            -- A broad principal nested (any depth) in a listed group.
            SELECT r.gmsa_guid, r.trustee_sid,
                   CASE WHEN m.object_sid LIKE 'S-1-5-21-%%-513' THEN 'Domain Users'
                        WHEN m.object_sid LIKE 'S-1-5-21-%%-514' THEN 'Domain Guests'
                        WHEN m.object_sid LIKE 'S-1-5-21-%%-515' THEN 'Domain Computers'
                        ELSE b.label END
                   || ' (via ' || COALESCE(t.sam_account_name, t.object_sid, t.object_guid::text) || ')'
            FROM readers r
            JOIN directory_object t
              ON t.object_sid = r.trustee_sid AND t.client_id = %(client_id)s
             AND t.object_class = 'group' AND NOT t.is_deleted
            JOIN v_effective_group_membership vem
              ON vem.group_guid = t.object_guid AND vem.client_id = t.client_id
            JOIN directory_object m
              ON m.object_guid = vem.member_guid AND m.client_id = vem.client_id AND NOT m.is_deleted
            LEFT JOIN broad b ON b.sid = m.object_sid
            WHERE b.sid IS NOT NULL
               OR m.object_sid LIKE 'S-1-5-21-%%-513'
               OR m.object_sid LIKE 'S-1-5-21-%%-514'
               OR m.object_sid LIKE 'S-1-5-21-%%-515'
        ),
        per_gmsa AS (
            SELECT gmsa_guid,
                   string_agg(DISTINCT label, ', ' ORDER BY label) AS label_list,
                   jsonb_agg(DISTINCT jsonb_build_object('trustee_sid', trustee_sid, 'principal', label)) AS broad_readers
            FROM broad_match
            GROUP BY gmsa_guid
        )
        SELECT
            CASE WHEN g.is_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.is_enabled IS FALSE THEN 'medium' ELSE 'critical' END AS fd_severity,
            'gMSA ' || COALESCE(g.sam_account_name, g.object_guid::text)
                || ' password is retrievable by ' || p.label_list
                || CASE WHEN g.is_enabled IS FALSE THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'broad_readers', p.broad_readers,
                'is_enabled', g.is_enabled
            ) AS detail
        FROM per_gmsa p
        JOIN ad_computer g
          ON g.object_guid = p.gmsa_guid
         AND g.client_id = %(client_id)s
         AND g.valid_to IS NULL
        ORDER BY g.object_guid
    """,
}
