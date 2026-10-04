"""
Plugin 5015: Schema Default Security Descriptor Modified (Persistence)

Detects tampering with the defaultSecurityDescriptor of the schema
classes whose objects matter most: user, computer, group,
groupPolicyContainer, organizationalUnit, msDS-GroupManagedServiceAccount
and inetOrgPerson (ad_schema_object.default_security_descriptor, SDDL,
schema v38). The default security descriptor is copied into the
explicit DACL of every NEW object of the class, so a backdoor ACE there
(e.g. GenericAll for an attacker's account on the user class) silently
gives its holder control of every user, computer or GPO created from
then on -- and survives cleanup of existing objects' ACLs. Only Schema
Admins can change it, so a modification is either a deliberate, rare
product extension or persistence left by an attacker who once held
Tier 0 (MITRE ATT&CK T1484 / T1098, SpecterOps research on schema
persistence, Purple Knight).

The SDDL DACL is parsed in SQL: each "(type;flags;rights;object_guid;
inherit_object_guid;trustee)" ACE string of the D: part. A class is
flagged when its DACL contains:
  (1) any ACE whose trustee is an explicit domain SID (S-1-5-21-...).
      Microsoft's defaults name trustees only through SDDL aliases
      (DA, SY, AO, PS, AU, CO, CA, RS, ...) or builtin S-1-5-32-xxx SIDs,
      never a domain account or group; or
  (2) an allow ACE (A / OA) granting a write-type right -- GA, GW, WD,
      WO, WP, CC, DC (delete child), SD, DT, or SW / CR without an
      object GUID (all validated writes / all extended rights), or the
      equivalent bits of a hex rights mask -- to a broad principal:
      Everyone (WD), Authenticated Users (AU), Domain Users (DU), Domain
      Computers (DC), Builtin Users (BU), Anonymous (AN), Network (NU),
      Interactive (IU), Domain Guests (DG), Guests (BG) or Pre-Windows
      2000 Compatible Access (RU), by alias or by SID.
The real Windows Server defaults do not trigger either test: e.g. the
user class grants AU read (A;;RPLCLORC;;;AU) and object-scoped reads,
Everyone only the Change-Password extended right (OA;;CR;ab721a53-...;;WD),
SELF (PS) object-scoped writes and validated writes, Cert Publishers (CA)
write userCertificate, and the builtin Windows Authorization Access /
Terminal Server License Servers groups (S-1-5-32-560/561) object-scoped
reads/writes. A WD/AU CR right WITH an object GUID (a single extended
right such as Change-Password) is therefore not flagged; one without an
object GUID (All Extended Rights, incl. Reset Password) is.

high, one row per class. Classes whose descriptor was not collected
(NULL; before schema v38) are skipped. Not flagged: non-broad aliases
(e.g. a write grant to Account Operators or Creator Owner) and
reordered or removed default ACEs -- this is a targeted backdoor check,
not a full diff against the per-version default SDDL.
"""

PLUGIN = {
    "plugin_id": 5015,
    "category": "ACLs",
    "name": "Schema Default Security Descriptor Modified (Persistence)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "ACL-5015",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1098",
        "MITRE-ATTCK-T1484",
    ],
    "references": [
        {"title": "Microsoft: Default Security Descriptor (defaultSecurityDescriptor)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/ad/default-security-descriptor"},
        {"title": "Microsoft: Security Descriptor String Format (SDDL)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format"},
        {"title": "MITRE ATT&CK T1484: Domain or Tenant Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/"},
    ],
    "description": (
        "Flags the user, computer, group, groupPolicyContainer, "
        "organizationalUnit, msDS-GroupManagedServiceAccount and inetOrgPerson "
        "schema classes when their defaultSecurityDescriptor names an explicit "
        "domain SID (Microsoft defaults use only aliases) or grants a "
        "write-type right (GenericAll/GenericWrite/WriteDacl/WriteOwner/"
        "WriteProperty/Create/Delete child, all extended rights...) to "
        "Everyone, Authenticated Users, Domain Users, Domain Computers, Users, "
        "Anonymous or similar broad principals. Every new object of the class "
        "inherits such a backdoor ACE."
    ),
    "remediation": (
        "Compare the class's defaultSecurityDescriptor with the default for "
        "your schema version (Microsoft's published schema / a clean lab "
        "forest: `Get-ADObject \"CN=User,$((Get-ADRootDSE).schemaNamingContext)\" "
        "-Properties defaultSecurityDescriptor`), and as Schema Admin restore "
        "the default with `Set-ADObject ... -Replace "
        "@{defaultSecurityDescriptor='<default SDDL>'}` (enable schema writes "
        "on the schema master only for the change). Then find objects created "
        "since the change -- their explicit DACLs carry the backdoor ACE -- and "
        "reset their permissions (dsacls /S or Set-Acl), and investigate how "
        "Schema Admin rights were obtained. Keep Schema Admins empty."
    ),
    "base_severity": "high",
    "query": """
        WITH cls AS (
            SELECT s.object_guid,
                   COALESCE(s.ldap_display_name, s.schema_cn) AS class_name,
                   s.default_security_descriptor AS sd
            FROM ad_schema_object s
            JOIN directory_object o
              ON o.object_guid = s.object_guid AND o.client_id = s.client_id AND NOT o.is_deleted
            WHERE s.client_id = %(client_id)s
              AND s.valid_to IS NULL
              AND s.schema_object_type = 'classSchema'
              AND s.default_security_descriptor IS NOT NULL
              AND (lower(s.ldap_display_name) IN ('user', 'computer', 'group', 'grouppolicycontainer',
                                                 'organizationalunit', 'msds-groupmanagedserviceaccount',
                                                 'inetorgperson')
                   OR (s.ldap_display_name IS NULL
                       AND lower(s.schema_cn) IN ('user', 'computer', 'group', 'group-policy-container',
                                                  'organizational-unit',
                                                  'ms-ds-group-managed-service-account',
                                                  'inetorgperson')))
        ),
        dacl AS (
            -- the D: part only (stops before an S: SACL)
            SELECT c.object_guid, c.class_name, c.sd,
                   substring(c.sd FROM 'D:[A-Z]*((\\([^)]*\\))+)') AS aces
            FROM cls c
        ),
        ace AS (
            SELECT d.object_guid, d.class_name, m.n,
                   m.ace_str,
                   upper(split_part(m.ace_str, ';', 1)) AS ace_type,
                   upper(split_part(m.ace_str, ';', 3)) AS rights,
                   split_part(m.ace_str, ';', 4) AS object_guid_str,
                   upper(split_part(m.ace_str, ';', 6)) AS trustee
            FROM dacl d
            CROSS JOIN LATERAL (
                SELECT r[1] AS ace_str, row_number() OVER () AS n
                FROM regexp_matches(COALESCE(d.aces, ''), '\\(([^)]*)\\)', 'g') AS r
            ) m
        ),
        ace_eval AS (
            SELECT a.*,
                   -- normalise well-known SIDs written out as SIDs to aliases
                   CASE
                       WHEN a.trustee = 'S-1-1-0' THEN 'WD'
                       WHEN a.trustee = 'S-1-5-11' THEN 'AU'
                       WHEN a.trustee = 'S-1-5-7' THEN 'AN'
                       WHEN a.trustee = 'S-1-5-2' THEN 'NU'
                       WHEN a.trustee = 'S-1-5-4' THEN 'IU'
                       WHEN a.trustee = 'S-1-5-32-545' THEN 'BU'
                       WHEN a.trustee = 'S-1-5-32-546' THEN 'BG'
                       WHEN a.trustee = 'S-1-5-32-554' THEN 'RU'
                       WHEN a.trustee ~ '^S-1-5-21-[0-9-]+-513$' THEN 'DU'
                       WHEN a.trustee ~ '^S-1-5-21-[0-9-]+-514$' THEN 'DG'
                       WHEN a.trustee ~ '^S-1-5-21-[0-9-]+-515$' THEN 'DC'
                       ELSE a.trustee
                   END AS trustee_alias,
                   a.trustee ~ '^S-1-5-21-' AS explicit_domain_sid,
                   CASE
                       WHEN a.rights ~ '^0X[0-9A-F]+$' THEN
                           ((('x' || lpad(substr(a.rights, 3), 16, '0'))::bit(64)::bigint)
                              & (268435456 | 1073741824 | 262144 | 524288 | 32 | 1 | 2 | 65536 | 64)) <> 0
                           OR (a.object_guid_str = ''
                               AND ((('x' || lpad(substr(a.rights, 3), 16, '0'))::bit(64)::bigint)
                                    & (256 | 8)) <> 0)
                       ELSE EXISTS (
                           SELECT 1 FROM regexp_matches(a.rights, '..', 'g') AS t(tok)
                           WHERE t.tok[1] IN ('GA', 'GW', 'WD', 'WO', 'WP', 'CC', 'DC', 'SD', 'DT')
                              OR (t.tok[1] IN ('CR', 'SW') AND a.object_guid_str = '')
                       )
                   END AS grants_write
            FROM ace a
        ),
        flagged AS (
            SELECT e.*,
                   CASE WHEN e.explicit_domain_sid THEN 'explicit domain SID'
                        ELSE 'write right for broad principal' END AS reason
            FROM ace_eval e
            WHERE e.explicit_domain_sid
               OR (e.ace_type IN ('A', 'OA')
                   AND e.grants_write
                   AND e.trustee_alias IN ('WD', 'AU', 'DU', 'DC', 'BU', 'AN', 'NU', 'IU',
                                           'DG', 'BG', 'RU'))
        )
        SELECT
            'fail' AS status,
            f.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Schema class ' || f.class_name || ' default security descriptor contains '
                || count(*) || ' non-default ACE(s) that every new object inherits: '
                || string_agg('(' || f.ace_str || ')', ' ' ORDER BY f.n) AS summary,
            jsonb_build_object(
                'class', f.class_name,
                'flagged_aces', jsonb_agg(jsonb_build_object(
                    'ace', f.ace_str,
                    'trustee', f.trustee,
                    'rights', f.rights,
                    'reason', f.reason
                ) ORDER BY f.n)
            ) AS detail
        FROM flagged f
        GROUP BY f.object_guid, f.class_name
    """,
}
