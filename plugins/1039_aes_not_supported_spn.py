"""
Plugin 1039: Service Account (SPN-Bearing) Does Not Support AES Encryption -- RETIRED 2026-10-03

Retired as a duplicate of plugin 1024 (SPN-Bearing User Account Does Not
Support AES Kerberos Encryption). Both used the identical filter --
enabled ad_user rows with at least one SPN and neither AES bit (0x8/0x10)
in msDS-SupportedEncryptionTypes -- so every account was reported twice
for the same object_guid, once here at a flat 'low' and once by 1024.

1024 is kept because it has the better severity model: medium by
default, escalated to high when the account is privileged (admin_count=1
or any row in v_privileged_principal), which is exactly the case where a
cracked RC4 service ticket hurts most.

Folded into 1024 v1.5: the MS-KILE and PingCastle S-AesNotEnabled
references, the remediation note that the password must be reset once
after enabling AES for AES keys to exist (and the gMSA note), and the
pwd_last_set detail key.

adaudit does not run retired plugins; it closes this plugin's open
findings with change_status 'retired' and records the successor.
"""

PLUGIN = {
    "plugin_id": 1039,
    "name": "Service Account (SPN-Bearing) Does Not Support AES Encryption",
    "retired": True,
    "superseded_by": 1024,
    "revision_date": "2026-10-03",
}
