"""
Plugin 4023: Domain Controller Computer Object Not Owned by an Expected Principal -- RETIRED 2026-10-03

Retired as a duplicate of plugin 2030 (Domain Controller Computer Object
Owned by an Unexpected Principal). Both checked directory_object.owner_sid
of every DC computer object, on the same object_guid, but with
conflicting allow-lists: 4023 flagged (medium) the RID-500 Administrator
and BUILTIN\\Administrators owners that 2030 accepted, while 2030 flagged
(high) everything else -- so one DC could get two findings with
different severities for one owner.

2030 v1.1 consolidates both with a single tiered model:
  - Domain Admins (-512) / Enterprise Admins (-519): expected, no finding.
  - BUILTIN\\Administrators, the RID-500 account, SYSTEM: Tier 0 already,
    reported as a low-severity hygiene deviation (the case only 4023
    used to report).
  - Any other principal that is privileged per v_privileged_principal:
    medium deviation.
  - A non-Tier-0 principal, or an owner SID that does not resolve: high.
4023's PingCastle P-DCOwner reference, dns_hostname detail key and
promotion-residue explanation were folded into 2030.

Retiring 4023 also removes its control_id "DOM-423", which collided with
plugin 4022 (DOM-423 stays with 4022, matching the DOM-421/422/424
sequence of its neighbors).

adaudit does not run retired plugins; it closes this plugin's open
findings with change_status 'retired' and records the successor.
"""

PLUGIN = {
    "plugin_id": 4023,
    "name": "Domain Controller Computer Object Not Owned by an Expected Principal",
    "retired": True,
    "superseded_by": 2030,
    "revision_date": "2026-10-03",
}
