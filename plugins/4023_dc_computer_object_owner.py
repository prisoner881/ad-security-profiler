"""
Plugin 4023: Domain Controller Computer Object Not Owned by an Expected Principal

By default, a domain controller's own computer object is owned by
Domain Admins or Enterprise Admins. A different owner is most commonly
residue from how the DC was originally promoted (e.g. promoted by an
account that was a Domain Admin at the time but was later demoted, or
promoted from an already-existing server object joined to the domain
by someone else beforehand) rather than deliberate tampering -- but
whoever holds ownership of an object can always rewrite its ACL
outright, regardless of what the ACL currently says, making an
unexpected owner on a domain controller's own account object worth a
second look regardless of how it got there.

Owner data comes from a targeted, DC-only security descriptor read
added specifically to support this plugin (adprofiler.py v0.5.5) --
domain controllers are typically few in number, the same low-cost
profile as the existing domain root/AdminSDHolder targeted reads, and
deliberately scoped to owner extraction only (not full ACE scanning,
which wasn't requested and would add LDAP read cost with nothing
currently using it).
"""

PLUGIN = {
    "plugin_id": 4023,
    "category": "Domain",
    "name": "Domain Controller Computer Object Not Owned by an Expected Principal",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "Review who currently owns this DC's computer object and "
        "confirm it's expected. If not, change ownership to Domain "
        "Admins: open the object in ADSI Edit or Active Directory "
        "Users and Computers (Advanced Features enabled) -> Properties "
        "-> Security tab -> Advanced -> Owner -> change to Domain "
        "Admins. Whoever holds ownership of an object can always "
        "rewrite its ACL regardless of what the ACL currently allows, "
        "so an unexpected owner is worth resolving even if the DC's "
        "current ACL itself looks otherwise correct."
    ),
    "control_id": "DOM-423",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: ACL Check rules -- P-DCOwner",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A domain controller's own computer object is owned by a "
        "principal other than Domain Admins or Enterprise Admins. Most "
        "commonly residue from how the DC was originally promoted "
        "(promoted by an account that was privileged at the time but "
        "isn't now, or promoted from an already-existing computer "
        "object) rather than deliberate tampering -- but ownership "
        "always permits rewriting an object's ACL outright regardless "
        "of the ACL's current content, so an unexpected owner is worth "
        "reviewing regardless of how it arose."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain Controller ' || c.sam_account_name || ' is owned by '
                || COALESCE(owner_do.sam_account_name, do2.owner_sid)
                || ', not Domain Admins/Enterprise Admins' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'owner_sid', do2.owner_sid,
                'owner_sam_account_name', owner_do.sam_account_name
            ) AS detail
        FROM ad_computer c
        JOIN directory_object do2 ON do2.object_guid = c.object_guid AND do2.client_id = c.client_id
        LEFT JOIN directory_object owner_do
            ON owner_do.object_sid = do2.owner_sid AND owner_do.client_id = do2.client_id
        WHERE c.client_id = %(client_id)s
          AND c.valid_to IS NULL
          AND c.is_domain_controller
          AND do2.owner_sid IS NOT NULL
          AND do2.owner_sid NOT LIKE '%%-512'
          AND do2.owner_sid NOT LIKE '%%-519'
    """,
}
