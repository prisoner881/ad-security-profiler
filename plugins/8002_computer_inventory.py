"""
Plugin 8002: Computer Inventory

A utility plugin, not a finding plugin: see plugin 8001's docstring
for the full design rationale of this second, parallel plugin type.
Runs fresh every invocation, no persistence, no change tracking.

[v1.1] Adds enabled state, DNS host name and domain-controller /
read-only-DC classification (is_domain_controller covers RODCs since
schema v36) as trailing columns.
"""

PLUGIN = {
    "plugin_id": 8002,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "Computer Inventory",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "description": (
        "Snapshot listing of every computer account: name, last logon "
        "timestamp, last password change, object creation date, and "
        "operating system with version, enabled state, DNS host name, "
        "and whether it is a (read-only) domain controller."
    ),
    "query": """
        SELECT
            c.sam_account_name,
            c.last_logon_timestamp,
            c.pwd_last_set,
            c.when_created,
            c.operating_system,
            c.operating_system_version,
            c.is_enabled,
            c.dns_hostname,
            c.is_domain_controller,
            c.is_read_only_dc
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
        ORDER BY c.sam_account_name
    """,
}
