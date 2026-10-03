"""
Plugin 2008: Computer Account Holds Unexpected Privileged Access

A workstation or member server's machine account is not normally
expected to hold privileged access at all -- whether via membership in
an AdminSDHolder-protected group (the original, sole check this plugin
performed), or, as of this version, directly holding dangerous rights
or DCSync rights on the domain root/AdminSDHolder, or owning either
object outright. Any of the three means anyone who achieves SYSTEM-level
access on that machine (a much lower bar than compromising a human's
credentials directly -- SYSTEM access is the routine outcome of
countless common exploitation and misconfiguration paths) inherits that
privileged access along with it.

[v1.2] Broadened from group-membership-only to also recognize
ACL-derived privilege, mirroring the identical enhancement applied to
the equivalent user-account privileged_check CTE. The summary text now
correctly names whichever mechanism(s) actually apply, rather than
always claiming group membership -- a real, if narrow, accuracy risk
found while making this change: a naive broadening of the trigger
condition without also updating the summary construction would have
produced a factually wrong "is a member of a privileged group" claim
for a computer that was actually privileged via a direct ACE or
ownership instead.

[v1.4] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34). The old ACL and ownership checks
counted a dangerous right on, or ownership of, ANY object -- despite the
summary saying "domain root/AdminSDHolder" -- so a machine account with
delegation on an ordinary OU, or that owned an ordinary object, was
reported. Now only rights on, or ownership of, a Tier 0 object count
(domain root, AdminSDHolder, DCs, CAs, PKI containers, protected groups,
...), plus DCSync and membership in a group holding any of those (a new
summary clause, previously missed entirely). The original summary wording
is kept when the object is the domain root or AdminSDHolder; other Tier 0
objects get "a Tier 0 object". detail gains via_holder_group and
privilege_sources.
"""

PLUGIN = {
    "plugin_id": 2008,
    "category": "Computer Accounts",
    "name": "Computer Account Holds Unexpected Privileged Access",
    "version": "1.4",
    "revision_date": "2026-10-03",
    "remediation": (
        "Determine why this computer account holds this access -- it is "
        "almost never an intentional, necessary configuration for an "
        "ordinary workstation or member server. If it was added for a "
        "specific automation/service purpose, replace it with a properly "
        "scoped service account or gMSA instead of granting the privilege "
        "to the machine account itself, then remove the access. If it "
        "cannot be explained, treat it as a potential compromise "
        "indicator and investigate before simply removing it, since "
        "removal alone won't explain how it got there."
    ),
    "control_id": "PRIV-201",
    "framework_tags": [],
    "references": [],
    "description": (
        "A workstation or member server's machine account is not "
        "normally expected to hold privileged access at all -- domain "
        "controllers are the one legitimate, expected exception and are "
        "excluded from this check. Uses the shared Tier 0 definition "
        "(v_privileged_principal, the same one the equivalent user-account "
        "checks use): membership, direct or nested, in an AdminSDHolder-"
        "protected group; holding GenericAll/GenericWrite/WriteDacl/"
        "WriteOwner on a Tier 0 object (domain root, AdminSDHolder, a DC, "
        "a CA, ...) or DCSync rights on the domain root; owning a Tier 0 "
        "object outright; or membership in a group that does any of "
        "these. Any of them means anyone who achieves SYSTEM-level access on this "
        "machine -- a routine outcome of a very wide range of common "
        "exploitation paths, a much lower bar than compromising a "
        "specific human's credentials -- inherits that privileged access "
        "along with it. "
        "NOT downgraded when disabled: this kind of privilege is persistent configuration unaffected by the account's enabled state."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_sources AS (
            -- [v1.4] One row per (principal, reason, via object) from the
            -- shared Tier 0 view (schema v34), replacing an inline
            -- subquery that counted GenericAll/GenericWrite/WriteDACL/
            -- WriteOwner on, or ownership of, ANY object -- so a machine
            -- account with delegation on an ordinary OU, or owning an
            -- ordinary object, was reported as privileged.
            -- at_root_or_adminsdholder keeps the original summary wording
            -- for the domain root/AdminSDHolder case, the one the old
            -- wording described; other Tier 0 objects (DCs, CAs, PKI
            -- containers, ...) get their own wording.
            SELECT p.object_guid, p.privilege_source,
                   EXISTS (SELECT 1 FROM v_tier0_object t
                           WHERE t.client_id = p.client_id
                             AND t.object_guid = p.via_object_guid
                             AND t.tier0_reason IN ('domain_root', 'adminsdholder')) AS at_root_or_adminsdholder
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
        ),
        privileged_agg AS (
            SELECT object_guid,
                   bool_or(privilege_source = 'protected_group_member') AS via_group,
                   bool_or(privilege_source IN ('tier0_acl_control', 'dcsync')) AS via_acl,
                   bool_or(privilege_source IN ('tier0_acl_control', 'dcsync')
                           AND NOT at_root_or_adminsdholder) AS via_acl_other_tier0,
                   bool_or(privilege_source = 'tier0_ownership') AS via_owner,
                   bool_or(privilege_source = 'tier0_ownership'
                           AND NOT at_root_or_adminsdholder) AS via_owner_other_tier0,
                   bool_or(right(privilege_source, 10) = '_via_group') AS via_holder_group,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM privileged_sources
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Computer Account ' || c.sam_account_name || ' holds privileged access: ' || (
                SELECT string_agg(x, '; ') FROM (VALUES
                    (CASE WHEN pa.via_group THEN 'member of a privileged (AdminSDHolder-protected) group' END),
                    (CASE WHEN pa.via_acl AND NOT pa.via_acl_other_tier0
                          THEN 'directly holds dangerous or DCSync rights on the domain root/AdminSDHolder'
                          WHEN pa.via_acl
                          THEN 'directly holds dangerous or DCSync rights on a Tier 0 object' END),
                    (CASE WHEN pa.via_owner AND NOT pa.via_owner_other_tier0
                          THEN 'owns the domain root or AdminSDHolder'
                          WHEN pa.via_owner
                          THEN 'owns a Tier 0 object' END),
                    (CASE WHEN pa.via_holder_group
                          THEN 'member of a group that holds dangerous or DCSync rights on, or owns, a Tier 0 object' END)
                ) AS v(x) WHERE x IS NOT NULL
            ) AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'via_group', pa.via_group,
                'via_acl', pa.via_acl,
                'via_owner', pa.via_owner,
                'via_holder_group', pa.via_holder_group,
                'privilege_sources', pa.privilege_sources
            ) AS detail
        FROM ad_computer c
        JOIN privileged_agg pa ON pa.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND NOT c.is_domain_controller
    """,
}

