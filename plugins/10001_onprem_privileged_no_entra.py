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

[v1.2] Reframed as informational. Microsoft's hybrid-admin guidance is NOT
to synchronize on-prem privileged accounts (use cloud-only Entra admins),
so an unsynced Tier 0 account is usually the desired state: fd_severity is
now 'info'. The population is now current Tier 0 privilege
(v_privileged_principal) instead of the sticky adminCount=1, enabled
accounts only, excluding the built-in Administrator (RID 500) and krbtgt
(RID 502), which Entra Connect's default scoping never synchronizes. Only
evaluated when the tenant is actually hybrid (at least one entra_user with
on_premises_sync_enabled) -- in a cloud-only tenant every on-prem account
trivially has no Entra match.
"""

PLUGIN = {
    "plugin_id": 10001,
    "category": "Hybrid Identity",
    "name": "On-Prem Privileged Account Has No Corresponding Entra Identity",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.004"],
    "references": [
        "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks",
    ],
    "description": (
        "Informational: an enabled on-prem account holding current Tier 0 "
        "privilege (v_privileged_principal; built-in Administrator and "
        "krbtgt excluded) with no corresponding Entra user. Microsoft "
        "recommends NOT synchronizing on-prem privileged accounts, so this "
        "is usually the intended state; it is surfaced so an unintended "
        "sync-scoping gap can be told apart from a deliberate exclusion. "
        "Only evaluated when the tenant is hybrid (at least one entra_user "
        "row with on_premises_sync_enabled)."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            udo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'Privileged on-prem account ' || udo.sam_account_name
                || ' has no corresponding Entra identity' AS summary,
            jsonb_build_object('sam_account_name', udo.sam_account_name) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled IS TRUE
          AND udo.object_sid !~ '-50[02]$'
          AND EXISTS (SELECT 1 FROM v_privileged_principal pp
                       WHERE pp.client_id = u.client_id AND pp.object_guid = u.object_guid)
          AND EXISTS (SELECT 1 FROM entra_user eu
                       WHERE eu.client_id = %(client_id)s AND eu.on_premises_sync_enabled IS TRUE)
          AND NOT EXISTS (
                SELECT 1 FROM entra_user eu
                WHERE eu.client_id = %(client_id)s AND eu.on_prem_object_guid = u.object_guid
              )
    """,
}
