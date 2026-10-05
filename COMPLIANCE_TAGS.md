# Compliance framework tags

Every finding plugin's `PLUGIN["framework_tags"]` lists the compliance controls and threat references the check gives evidence for. `adaudit.py` copies them into `control_catalog.framework_tags` and builds the **Compliance** sheets of the Excel workbook from them. Those sheets show, per framework and per control, which plugins test it and whether they passed.

A tag means "a failure of this plugin is evidence against this control". It does not mean the plugin fully tests the control. Most controls have parts no directory scan can see, such as process, review cadence or documentation.

## Format

Tags are plain strings: `<FRAMEWORK PREFIX><control id>`. The prefix decides which framework sheet a tag lands on. Use exactly these prefixes and spell the control ID as the framework publishes it.

| Prefix | Framework | Example |
|---|---|---|
| `NIST-800-53-` | NIST SP 800-53 Rev. 5 | `NIST-800-53-AC-2(3)` |
| `NIST-CSF-2.0-` | NIST Cybersecurity Framework 2.0 | `NIST-CSF-2.0-PR.AA-05` |
| `PCI-DSS-4.0-` | PCI DSS v4.0 / v4.0.1 | `PCI-DSS-4.0-8.2.6` |
| `CIS-CSC-8-` | CIS Critical Security Controls v8 (safeguards) | `CIS-CSC-8-5.4` |
| `ISO-27001-2022-` | ISO/IEC 27001:2022 Annex A | `ISO-27001-2022-A.8.2` |
| `SOC2-` | AICPA SOC 2 Trust Services Criteria (2017, rev. 2022) | `SOC2-CC6.1` |
| `HIPAA-` | HIPAA Security Rule, 45 CFR | `HIPAA-164.312(d)` |
| `CISA-SCUBA-` | CISA SCuBA Microsoft Entra ID baseline | `CISA-SCUBA-MS.AAD.7.1` |
| `DISA-STIG` | DISA Active Directory Domain / Forest STIG | `DISA-STIG` or `DISA-STIG-V-243503` |
| `MITRE-ATTCK-` | MITRE ATT&CK Enterprise technique | `MITRE-ATTCK-T1558.003` |
| `CVE-` | A specific vulnerability the check detects exposure to | `CVE-2021-42278` |
| `CISA-` (other) | A CISA advisory / directive the check addresses | `CISA-AA26-237A`, `CISA-ED-24-02` |

Rules:

- **Only use control IDs from the crib below.** Its IDs have been checked against the published framework texts. If a plugin needs a control the crib doesn't have, add it to the crib in the same change, with its title.
- **`DISA-STIG-V-<n>`:** use only when the plugin already cites that exact rule (in `stig_reference`, its docstring or its references). Otherwise use the bare `DISA-STIG` when a STIG requirement plainly covers the check.
- **MITRE ATT&CK:** use the most specific technique or sub-technique the finding enables.
- **Entra plugins:** tag SCuBA controls only where the plugin tests that policy's condition.
- **Inventory plugins** carry no tags.
- **Order:** the order of tags in the list doesn't matter, but keep one tag per string and no duplicates.

## Topic crib

Pick the topic(s) the plugin is evidence for and use their tags. A plugin usually maps to one to three topics. Don't tag a topic the check only loosely touches.

### T1. Account lifecycle: dormant, disabled, expired, orphaned accounts
`NIST-800-53-AC-2`, `NIST-800-53-AC-2(3)`, `NIST-CSF-2.0-PR.AA-01`, `PCI-DSS-4.0-8.2.6`, `CIS-CSC-8-5.3`, `ISO-27001-2022-A.5.18`, `SOC2-CC6.2`, `HIPAA-164.308(a)(3)(ii)(C)`

### T2. Unique identification; shared, generic and default accounts
`NIST-800-53-IA-2`, `NIST-800-53-IA-4`, `NIST-800-53-AC-2(9)`, `PCI-DSS-4.0-8.2.1`, `PCI-DSS-4.0-8.2.2`, `PCI-DSS-4.0-2.2.2`, `CIS-CSC-8-4.7`, `ISO-27001-2022-A.5.16`, `SOC2-CC6.1`, `HIPAA-164.312(a)(2)(i)`

### T3. Privileged account management: membership of admin groups, admin account hygiene, separation of admin and daily-use accounts
`NIST-800-53-AC-2(7)`, `NIST-800-53-AC-6(5)`, `NIST-800-53-AC-6(2)`, `NIST-CSF-2.0-PR.AA-05`, `PCI-DSS-4.0-7.2.1`, `PCI-DSS-4.0-7.2.2`, `CIS-CSC-8-5.4`, `CIS-CSC-8-6.8`, `ISO-27001-2022-A.8.2`, `SOC2-CC6.3`, `HIPAA-164.308(a)(4)(ii)(B)`

### T4. Access control permissions: ACLs, delegated rights, ownership, delegation of authentication (Kerberos delegation, RBCD), DCSync rights
`NIST-800-53-AC-3`, `NIST-800-53-AC-6`, `NIST-800-53-AC-6(1)`, `NIST-CSF-2.0-PR.AA-05`, `PCI-DSS-4.0-7.2.1`, `PCI-DSS-4.0-7.2.2`, `CIS-CSC-8-3.3`, `CIS-CSC-8-6.8`, `ISO-27001-2022-A.5.15`, `ISO-27001-2022-A.8.3`, `SOC2-CC6.3`, `HIPAA-164.312(a)(1)`

### T5. Password policy and authenticator strength: length, complexity, history, age, lockout, password-not-required
`NIST-800-53-IA-5`, `NIST-800-53-IA-5(1)`, `NIST-800-53-AC-7`, `NIST-CSF-2.0-PR.AA-01`, `PCI-DSS-4.0-8.3.4`, `PCI-DSS-4.0-8.3.6`, `PCI-DSS-4.0-8.3.7`, `PCI-DSS-4.0-8.3.9`, `CIS-CSC-8-5.2`, `ISO-27001-2022-A.5.17`, `SOC2-CC6.1`, `HIPAA-164.308(a)(5)(ii)(D)`

Use only the PCI sub-requirement(s) that match: 8.3.4 lockout, 8.3.6 length/complexity, 8.3.7 history, 8.3.9 age.

### T6. Credential exposure and storage: cleartext or reversible passwords, passwords in descriptions or scripts, readable secrets (LAPS, gMSA, DKM, KDS), roastable hashes
`NIST-800-53-IA-5(1)`, `NIST-800-53-SC-28`, `NIST-CSF-2.0-PR.DS-01`, `PCI-DSS-4.0-8.3.2`, `PCI-DSS-4.0-8.6.2`, `CIS-CSC-8-3.11`, `ISO-27001-2022-A.5.17`, `SOC2-CC6.1`, `HIPAA-164.312(a)(2)(iv)`

### T7. Service and system accounts
`NIST-800-53-AC-2`, `NIST-800-53-IA-5`, `PCI-DSS-4.0-8.6.1`, `PCI-DSS-4.0-8.6.3`, `PCI-DSS-4.0-7.2.5`, `CIS-CSC-8-5.5`, `ISO-27001-2022-A.5.17`, `SOC2-CC6.1`

### T8. Multi-factor and strong authentication: smart card, MFA, phishing-resistant MFA, legacy authentication, Kerberos pre-authentication, Protected Users
`NIST-800-53-IA-2(1)`, `NIST-800-53-IA-2(2)`, `NIST-800-53-IA-2(8)`, `NIST-CSF-2.0-PR.AA-03`, `PCI-DSS-4.0-8.4.1`, `PCI-DSS-4.0-8.4.2`, `PCI-DSS-4.0-8.4.3`, `CIS-CSC-8-6.3`, `CIS-CSC-8-6.4`, `CIS-CSC-8-6.5`, `ISO-27001-2022-A.8.5`, `SOC2-CC6.1`, `HIPAA-164.312(d)`

Use only the parts that match. For example, Kerberos pre-auth and replay resistance → IA-2(8) and ISO A.8.5, but not the PCI MFA requirements.

### T9. Cryptography: weak Kerberos encryption types (DES/RC4), missing AES keys, weak certificate keys or hashes, certificate and key lifecycle, PKI trust
`NIST-800-53-SC-12`, `NIST-800-53-SC-13`, `NIST-800-53-SC-17`, `NIST-800-53-IA-5(2)`, `NIST-CSF-2.0-PR.DS-02`, `PCI-DSS-4.0-4.2.1.1`, `PCI-DSS-4.0-12.3.3`, `CIS-CSC-8-3.10`, `ISO-27001-2022-A.8.24`, `SOC2-CC6.1`, `HIPAA-164.312(e)(1)`

Use SC-17, IA-5(2) and PCI 4.2.1.1 only for PKI/certificate checks, and SC-12 only for key management.

### T10. Secure configuration and hardening: domain/forest settings, dSHeuristics, MachineAccountQuota, schema, GPO baseline, DNS settings, optional features
`NIST-800-53-CM-6`, `NIST-800-53-CM-7`, `NIST-800-53-CM-2`, `NIST-CSF-2.0-PR.PS-01`, `PCI-DSS-4.0-2.2.1`, `PCI-DSS-4.0-2.2.4`, `PCI-DSS-4.0-2.2.6`, `CIS-CSC-8-4.1`, `CIS-CSC-8-4.8`, `ISO-27001-2022-A.8.9`, `SOC2-CC7.1`, `HIPAA-164.312(c)(1)`

Use 2.2.4 / CIS 4.8 only for unnecessary services or protocols.

### T11. Vulnerabilities, patching and unsupported software: CVE-specific exposures, unsupported OS, outdated schema/adprep
`NIST-800-53-SI-2`, `NIST-800-53-RA-5`, `NIST-800-53-SA-22`, `NIST-CSF-2.0-ID.RA-01`, `NIST-CSF-2.0-PR.PS-02`, `PCI-DSS-4.0-6.3.3`, `PCI-DSS-4.0-12.3.4`, `CIS-CSC-8-2.2`, `CIS-CSC-8-7.3`, `ISO-27001-2022-A.8.8`, `SOC2-CC7.1`

Use SA-22, 12.3.4, CIS 2.2 and PR.PS-02 only for unsupported/end-of-life software. Add the `CVE-` tag itself.

### T12. Backup and recovery: AD backups, Recycle Bin, tombstone lifetime, DSRM
`NIST-800-53-CP-9`, `NIST-800-53-CP-10`, `NIST-CSF-2.0-PR.DS-11`, `CIS-CSC-8-11.2`, `CIS-CSC-8-11.3`, `ISO-27001-2022-A.8.13`, `SOC2-A1.2`, `HIPAA-164.308(a)(7)(ii)(A)`

### T13. Change detection and monitoring: new or changed privileged membership, ACLs, trusts, DCs, GPOs, settings since the last run
`NIST-800-53-CM-3`, `NIST-800-53-SI-4`, `NIST-800-53-AU-6`, `NIST-800-53-AC-2(4)`, `NIST-CSF-2.0-DE.CM-03`, `NIST-CSF-2.0-DE.CM-09`, `PCI-DSS-4.0-10.2.1.2`, `PCI-DSS-4.0-10.2.1.5`, `PCI-DSS-4.0-11.5.2`, `CIS-CSC-8-8.11`, `ISO-27001-2022-A.8.16`, `ISO-27001-2022-A.8.32`, `SOC2-CC7.2`, `SOC2-CC8.1`, `HIPAA-164.308(a)(1)(ii)(D)`

Use AC-2(4) and PCI 10.2.1.5 for account and credential changes, and PCI 11.5.2 / A.8.32 / CC8.1 for configuration changes.

### T14. Trusts and external connections
`NIST-800-53-AC-4`, `NIST-800-53-AC-20`, `NIST-800-53-SC-7`, `NIST-CSF-2.0-PR.AA-05`, `CIS-CSC-8-12.2`, `ISO-27001-2022-A.8.20`, `ISO-27001-2022-A.8.22`, `SOC2-CC6.6`

### T15. Asset inventory: computers, DCs, subnets, sites
`NIST-800-53-CM-8`, `NIST-CSF-2.0-ID.AM-01`, `PCI-DSS-4.0-12.5.1`, `CIS-CSC-8-1.1`, `ISO-27001-2022-A.5.9`, `SOC2-CC6.1`

### T16. Cloud identity governance (Entra): app registration and consent, guest access, cloud-only admins, role assignment model (PIM / JIT)
`NIST-800-53-AC-2(7)`, `NIST-800-53-AC-6`, `NIST-800-53-CM-11`, `NIST-800-53-AC-20`, `NIST-CSF-2.0-PR.AA-05`, `PCI-DSS-4.0-7.2.1`, `PCI-DSS-4.0-8.2.7`, `CIS-CSC-8-6.7`, `ISO-27001-2022-A.5.23`, `ISO-27001-2022-A.5.19`, `SOC2-CC6.3`

Use CM-11 for user app consent and registration, and AC-20 / PCI 8.2.7 / A.5.19 for guests and external access.

### T17. Audit logging configuration: which security events domain controllers record (audit policy)
`NIST-800-53-AU-2`, `NIST-800-53-AU-12`, `NIST-800-53-AU-3`, `NIST-CSF-2.0-DE.CM-03`, `PCI-DSS-4.0-10.2.1`, `PCI-DSS-4.0-10.2.1.2`, `PCI-DSS-4.0-10.2.1.5`, `CIS-CSC-8-8.2`, `CIS-CSC-8-8.5`, `ISO-27001-2022-A.8.15`, `SOC2-CC7.2`, `HIPAA-164.312(b)`

### CISA SCuBA Entra ID (MS.AAD)

| Tag | Policy |
|---|---|
| `CISA-SCUBA-MS.AAD.1.1` | Legacy authentication SHALL be blocked |
| `CISA-SCUBA-MS.AAD.2.1` | Users detected as high risk SHALL be blocked |
| `CISA-SCUBA-MS.AAD.2.3` | Sign-ins detected as high risk SHALL be blocked |
| `CISA-SCUBA-MS.AAD.3.1` | Phishing-resistant MFA SHALL be enforced for all users |
| `CISA-SCUBA-MS.AAD.3.2` | If phishing-resistant MFA isn't enforced, an alternative MFA method SHALL be enforced for all users |
| `CISA-SCUBA-MS.AAD.3.6` | Phishing-resistant MFA SHALL be required for highly privileged roles |
| `CISA-SCUBA-MS.AAD.5.1` | Only administrators SHALL be allowed to register applications |
| `CISA-SCUBA-MS.AAD.5.2` | Only administrators SHALL be allowed to consent to applications |
| `CISA-SCUBA-MS.AAD.5.3` | An admin consent workflow SHALL be configured |
| `CISA-SCUBA-MS.AAD.7.1` | A minimum of two users and a maximum of eight users SHALL be provisioned with the Global Administrator role |
| `CISA-SCUBA-MS.AAD.7.2` | Privileged users SHALL be provisioned with finer-grained roles instead of Global Administrator |
| `CISA-SCUBA-MS.AAD.7.3` | Privileged users SHALL be provisioned cloud-only accounts separate from an on-premises directory |
| `CISA-SCUBA-MS.AAD.7.4` | Permanent active role assignments SHALL NOT be allowed for highly privileged roles |
| `CISA-SCUBA-MS.AAD.7.5` | Provisioning users to highly privileged roles SHALL NOT occur outside of a PAM system |
| `CISA-SCUBA-MS.AAD.7.7` | Eligible and Active highly privileged role assignments SHALL trigger an alert |
| `CISA-SCUBA-MS.AAD.8.1` | Guest users SHOULD have limited or restricted access to Entra ID directory objects |
| `CISA-SCUBA-MS.AAD.8.2` | Only users with the Guest Inviter role SHOULD be able to invite guest users |
