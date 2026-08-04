"""
Plugin 10001: On-Prem Privileged Account Has No Corresponding Entra Identity

The first of three findings only possible once both on-prem AD data
and Entra directory role/user data exist for the same client -- a
genuinely new category of finding this project couldn't build until
entra_graph_collector.py existed alongside adprofiler.py.

An AdminSDHolder-protected account (admin_count=1: Domain Admin,
Enterprise Admin, or effectively equivalent) with no corresponding
Entra user at all is either intentional -- a deliberately air-gapped
Tier-0 account, kept out of hybrid sync on purpose, which is a
legitimate and often recommended pattern for break-glass/emergency-
access accounts -- or a sync-scoping gap that was never meant to
exclude a privileged account specifically. This finding can't tell
those two apart on its own; it surfaces the fact so a human can.

Guarded on at least one entra_user row existing for this client:
without that, "no Entra match" is trivially true for every single
on-prem account, not because of anything meaningful about sync scope,
but simply because entra_graph_collector.py has never been run against
this client at all. Firing anyway in that case would be a false
positive dressed up as a finding, not a real gap.
"""

PLUGIN = {
    "plugin_id": 10001,
    "category": "Hybrid Identity",
    "name": "On-Prem Privileged Account Has No Corresponding Entra Identity",
    "version": "1.0",
    "revision_date": "2026-07-19",
    "remediation": (
        "Confirm whether this is deliberate. If this account is an "
        "intentionally air-gapped Tier-0/break-glass account kept out "
        "of hybrid sync on purpose, this finding is expected and can "
        "be documented as such. If it's not deliberate -- the account "
        "was simply never brought into scope for sync, or was "
        "explicitly filtered out by an Entra Connect sync rule without "
        "anyone realizing this specific account would be affected -- "
        "review the sync scoping configuration (OU-based filtering, "
        "attribute-based filtering rules) to confirm it's excluding "
        "this account for a real reason, not by accident."
    ),
    "control_id": "HYBRID-001",
    "framework_tags": [],
    "references": [],
    "description": (
        "An AdminSDHolder-protected on-prem account (admin_count=1) "
        "with no corresponding Entra user at all -- either a "
        "deliberately air-gapped Tier-0/break-glass account (a "
        "legitimate, often-recommended pattern) or an unintended sync-"
        "scoping gap. Can't distinguish the two on its own; surfaces "
        "the fact for review. Only evaluated when at least one "
        "entra_user row exists for this client, confirming Graph "
        "collection has actually run -- otherwise every on-prem "
        "account would trivially show no Entra match for a reason "
        "unrelated to sync scope."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            udo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Privileged on-prem account ' || udo.sam_account_name
                || ' has no corresponding Entra identity' AS summary,
            jsonb_build_object('sam_account_name', udo.sam_account_name) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.admin_count = 1
          AND EXISTS (SELECT 1 FROM entra_user eu WHERE eu.client_id = %(client_id)s)
          AND NOT EXISTS (
                SELECT 1 FROM entra_user eu
                WHERE eu.client_id = %(client_id)s AND eu.on_prem_object_guid = u.object_guid
              )
    """,
}
