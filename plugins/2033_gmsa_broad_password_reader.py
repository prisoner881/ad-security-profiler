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
"""

PLUGIN = {
    "plugin_id": 2033,
    "category": "Computer Accounts",
    "name": "gMSA Password Retrievable by an Overly Broad Principal",
    "version": "1.0",
    "revision_date": "2026-07-19",
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
    "framework_tags": [],
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
        "principals (Domain Computers, Domain Users, Authenticated "
        "Users, Everyone) in that list, which means every computer or "
        "user in the domain can retrieve the password -- functionally "
        "equivalent to not protecting it at all."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'gMSA ' || g.sam_account_name || ' password is retrievable by ' || (
                CASE
                    WHEN gr.trustee_sid LIKE '%%-513' THEN 'Domain Users'
                    WHEN gr.trustee_sid LIKE '%%-515' THEN 'Domain Computers'
                    WHEN gr.trustee_sid = 'S-1-5-11' THEN 'Authenticated Users'
                    WHEN gr.trustee_sid = 'S-1-1-0' THEN 'Everyone'
                END
            ) AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'trustee_sid', gr.trustee_sid,
                'ace_type', gr.ace_type
            ) AS detail
        FROM gmsa_password_reader_edge gr
        JOIN ad_computer g ON g.object_guid = gr.gmsa_guid AND g.valid_to IS NULL
        WHERE gr.client_id = %(client_id)s
          AND gr.valid_to IS NULL
          AND gr.ace_type = 'allow'
          AND (gr.trustee_sid LIKE '%%-513' OR gr.trustee_sid LIKE '%%-515'
               OR gr.trustee_sid = 'S-1-5-11' OR gr.trustee_sid = 'S-1-1-0')
    """,
}
