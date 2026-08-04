"""
Plugin 2031: Enabled Computer Account With No Password Ever Set

Automated provisioning tools (or legacy utilities such as dsadd) can
pre-create a computer account in Active Directory ahead of the actual
machine joining the domain. That pre-created object is deliberately
left with no password until the real join happens -- the join process
is what sets it. If the machine never actually joins (the project is
cancelled, the hardware is repurposed before setup finishes, or the
pre-creation was simply forgotten), the object is left permanently in
that no-password state: enabled, but with pwd_last_set never having
been set at all. Since a computer account with a known, predictable,
unset credential state is a soft target, an attacker who can identify
one of these objects has a much easier path to acting as that
computer than a normally-provisioned account would allow.
"""

PLUGIN = {
    "plugin_id": 2031,
    "category": "Computer Accounts",
    "name": "Enabled Computer Account With No Password Ever Set",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Confirm whether this computer account actually corresponds to "
        "a machine that is expected to join the domain soon. If the "
        "join was completed under a different computer object, or the "
        "provisioning was abandoned, disable or delete this orphaned "
        "pre-created account -- there is no reason to leave an enabled "
        "account with no password ever set sitting in the directory "
        "indefinitely."
    ),
    "control_id": "HYGIENE-201",
    "framework_tags": [],
    "references": [],
    "description": (
        "Automated provisioning tools can pre-create a computer "
        "account ahead of the actual machine joining the domain, "
        "deliberately left with no password until the join process "
        "sets one. If the machine never actually joins, the object is "
        "left permanently enabled with pwd_last_set never having been "
        "set at all -- a soft target with a known, predictable, unset "
        "credential state. Confirmed against Purple Knight's own "
        "equivalent check."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Computer Account ' || c.sam_account_name || ' is enabled but has never had a password set' AS summary,
            jsonb_build_object('sam_account_name', c.sam_account_name) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_enabled
          AND c.pwd_last_set IS NULL
    """,
}
