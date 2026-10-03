"""
Plugin 1011: User Account Supports Deprecated DES Kerberos Encryption -- RETIRED 2026-10-03

Retired as a duplicate of plugin 1038 (Account Configured to Allow DES
Kerberos Encryption), which is a strict superset of this check:

  - 1011 flagged enabled user accounts with msDS-SupportedEncryptionTypes
    bit 0x1 (DES-CBC-CRC) or 0x2 (DES-CBC-MD5) set, at high severity.
  - 1038 flags the same bits on users AND computers, enabled or disabled,
    and also the userAccountControl USE_DES_KEY_ONLY flag (0x200000), at
    the same high severity, and names which DES mechanisms are present.

Every account 1011 reported is therefore already reported by 1038 for the
same object_guid, so running both produced two findings for one issue.
1011's Microsoft encryption-types reference and its "target value 24
(AES128+AES256)" remediation guidance were folded into 1038 v1.1.

adaudit does not run retired plugins; it closes this plugin's open
findings with change_status 'retired' and records the successor.
"""

PLUGIN = {
    "plugin_id": 1011,
    "name": "User Account Supports Deprecated DES Kerberos Encryption",
    "retired": True,
    "superseded_by": 1038,
    "revision_date": "2026-10-03",
}
