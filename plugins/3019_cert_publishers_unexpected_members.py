"""
Plugin 3019: Cert Publishers Group Has Unexpected Members

The built-in Cert Publishers group exists so Enterprise/Standalone CA
computer accounts can publish issued certificates and certificate
revocation lists to Active Directory. Its only expected members are
CA server computer accounts themselves -- Microsoft's own
provisioning process adds the CA's computer account automatically
when the CA role is installed. Any OTHER kind of member (a regular
user or a computer that is not actually running a CA role) is
unexpected. Members of Cert Publishers can write to
certificateRevocationList and cACertificate-related attributes,
which -- depending on the exact object being written to -- can be a
step toward introducing a rogue, domain-trusted Certificate Authority.
"""

PLUGIN = {
    "plugin_id": 3019,
    "category": "Groups",
    "name": "Cert Publishers Group Has Unexpected Members",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Review every member listed in this finding's evidence. If a "
        "member is a computer account that IS actually running an "
        "Enterprise or Standalone CA role, this is expected and no "
        "action is needed. If a member is a user account, a computer "
        "that is not running a CA role, or a CA that has since been "
        "decommissioned, remove it -- there is no legitimate reason "
        "for anything other than an active CA server's own computer "
        "account to be here."
    ),
    "control_id": "PRIV-307",
    "framework_tags": [],
    "references": [],
    "description": (
        "The built-in Cert Publishers group exists so CA computer "
        "accounts can publish issued certificates and revocation lists "
        "to Active Directory. Its only expected members are CA server "
        "computer accounts, added automatically when the CA role is "
        "installed. Flags any member that is a user account, since a "
        "user account being a member is never an expected, automatic "
        "provisioning outcome the way a computer account is -- it "
        "means someone deliberately added it."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Cert Publishers group has ' || cnt.n
                || ' user account member(s), which is never an expected, automatically-provisioned member type' AS summary,
            jsonb_build_object(
                'member_count_direct', g.member_count_direct,
                'user_members', cnt.members
            ) AS detail
        FROM ad_group g
        JOIN LATERAL (
            SELECT count(*) AS n,
                   array_agg(mdo.sam_account_name ORDER BY mdo.sam_account_name) AS members
            FROM group_member_edge gme
            JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
            WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
              AND mdo.object_class = 'user'
        ) cnt ON cnt.n > 0
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.sam_account_name = 'Cert Publishers'
    """,
}
