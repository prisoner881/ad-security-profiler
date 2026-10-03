"""
Plugin 1014: Privileged Account Missing NOT_DELEGATED Protection -- RETIRED 2026-10-03

Retired as a duplicate of plugin 1041 (Privileged Account Missing the
"Cannot Be Delegated" Protection Flag). Both reported a privileged user
account without userAccountControl NOT_DELEGATED (0x100000) set, on the
same object_guid.

1041 is kept because it is the more accurate and better-mapped check:
it maps to DISA AD Domain STIG V-243470 (CAT I) and PingCastle
P-Delegated, rates the finding medium rather than an informational
'low', excludes krbtgt (RID 502), and defines "privileged" strictly
through v_privileged_principal (nested-membership aware).

What 1014 covered beyond 1041, and where it lives now:
  - Disabled privileged accounts (reported here at 'info'): covered by
    plugin 1042 (Disabled Account Still Holding Privilege), which is the
    right finding for them -- delegation is moot until re-enabled.
  - Accounts privileged only by a leftover admin_count=1: not actually
    privileged; the stale marker itself is plugin 1025's finding.
1014's `Set-ADAccountControl -AccountNotDelegated $true` remediation and
its MITRE ATT&CK T1558 reference were folded into 1041 v1.3.

adaudit does not run retired plugins; it closes this plugin's open
findings with change_status 'retired' and records the successor.
"""

PLUGIN = {
    "plugin_id": 1014,
    "name": "Privileged Account Missing NOT_DELEGATED Protection",
    "retired": True,
    "superseded_by": 1041,
    "revision_date": "2026-10-03",
}
