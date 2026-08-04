"""
Plugin 2012: Computer Account Description/Notes Field May Contain Password Material

Same technique as user-account plugin 1021, applied to computer objects.
Local admin passwords, BIOS passwords, or other machine-specific
credentials left in a computer's description/notes field are just as
readable by any authenticated domain user as the equivalent finding on a
user account.
"""

PLUGIN = {
    "plugin_id": 2012,
    "category": "Computer Accounts",
    "name": "Computer Account Description/Notes Field May Contain Password Material",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Remove the sensitive text from the field immediately, and treat "
        "the exposed credential as compromised -- rotate the local admin "
        "password (or whatever credential was exposed) on this machine "
        "specifically, and check whether the same password was reused on "
        "any other machine, which is common when a credential like this "
        "gets documented once and copied elsewhere."
    ),
    "control_id": "CRED-106",
    "framework_tags": [],
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
        "machine. "
        "NOT downgraded when disabled: the readable password value doesn't disappear when this account is disabled."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has a description/notes field that may contain a password' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'description', c.description,
                'notes', c.notes,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND (
                c.description ILIKE '%%pass%%' OR c.description ILIKE '%%pwd%%'
                OR c.notes ILIKE '%%pass%%' OR c.notes ILIKE '%%pwd%%'
              )
    """,
}
