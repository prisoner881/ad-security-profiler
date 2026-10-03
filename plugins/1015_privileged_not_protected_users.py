"""
Plugin 1015: Privileged Account Not a Member of Protected Users -- RETIRED 2026-10-03

Retired as a duplicate of plugin 1040 (Privileged Account Not a Member of
the Protected Users Group). Both reported a privileged user account that
is not in Protected Users (RID 525), on the same object_guid.

1040 is kept because it is the more accurate check: it resolves
Protected Users membership through v_effective_group_membership (so a
member via a nested group is correctly treated as protected, where
1015's ad_user.protected_users_member flag only reflects direct memberOf
and produced false positives), maps to DISA AD Domain STIG V-243477
(CAT II) and PingCastle P-ProtectedUsers, rates the finding medium
rather than 'low', and excludes krbtgt (RID 502).

What 1015 covered beyond 1040, and where it lives now:
  - Disabled privileged accounts (reported here at 'info'): covered by
    plugin 1042 (Disabled Account Still Holding Privilege).
  - Accounts privileged only by a leftover admin_count=1: not actually
    privileged; the stale marker itself is plugin 1025's finding.
  - Direct membership recorded in protected_users_member: 1040 v1.3 now
    also honors that flag, so an account never becomes a 1040 finding
    that 1015 considered protected (e.g. if the Protected Users group's
    membership edges were not collected).

adaudit does not run retired plugins; it closes this plugin's open
findings with change_status 'retired' and records the successor.
"""

PLUGIN = {
    "plugin_id": 1015,
    "name": "Privileged Account Not a Member of Protected Users",
    "retired": True,
    "superseded_by": 1040,
    "revision_date": "2026-10-03",
}
