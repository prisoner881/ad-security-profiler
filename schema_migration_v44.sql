-- ============================================================================
-- schema_migration_v44.sql
--
-- adprofiler.py 0.8.0 / sysvol_collector.py 1.1: data for six more
-- PingCastle-equivalent checks (plugins 1052, 4038, 4039, 9040-9042).
--
--   * ad_domain.dsheuristics: the whole dSHeuristics string (only
--     characters 7, 16 and 21 were kept until now), for List Object mode,
--     anonymous NSPI and the CVE-2021-42291 LDAP hardening (plugin 4038).
--   * ad_domain.ds_other_settings: msDS-Other-Settings of the same object,
--     for DenyUnauthenticatedBind (plugin 4039).
--   * ad_domain.netbios_name: so a share named \\CORP\NETLOGON is
--     recognised as the domain's own (plugins 1052, 9040, 9041).
--   * ad_user.script_path: the scriptPath logon script (plugin 1052).
--   * gpo_setting_edge source 'scripts': the commands in scripts.ini /
--     psscripts.ini (plugin 9040).
--   * gpo_preference_item_edge: Files and FolderOptions preference types
--     (plugins 9041, 9042); a comment change only, the column is free text.
--
-- adprofiler.py 0.8.0 rescans every object once on its first run (its
-- DERIVED_FIELDS_VERSION), so existing rows get the new columns.
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.ad_domain
    ADD COLUMN IF NOT EXISTS dsheuristics text,
    ADD COLUMN IF NOT EXISTS ds_other_settings jsonb,
    ADD COLUMN IF NOT EXISTS netbios_name text;
COMMENT ON COLUMN ad_intel.ad_domain.dsheuristics IS
    'The raw dSHeuristics string of CN=Directory Service,CN=Windows NT,CN=Services in the '
    'configuration partition (forest-wide). Empty string = attribute not set (all defaults); '
    'NULL = the object could not be read or was collected before adprofiler 0.8.0. Character n '
    'is substr(dsheuristics, n, 1). (schema v44)';
COMMENT ON COLUMN ad_intel.ad_domain.ds_other_settings IS
    'msDS-Other-Settings of the same Directory Service object as {"Name": "Value"} '
    '(e.g. {"DenyUnauthenticatedBind": "1"}). {} = attribute not set; NULL = unreadable or '
    'collected before adprofiler 0.8.0. (schema v44)';
COMMENT ON COLUMN ad_intel.ad_domain.netbios_name IS
    'The domain''s NetBIOS name (nETBIOSName of its crossRef in CN=Partitions). NULL = '
    'unreadable or collected before adprofiler 0.8.0. (schema v44)';

ALTER TABLE ad_intel.ad_user
    ADD COLUMN IF NOT EXISTS script_path text;
COMMENT ON COLUMN ad_intel.ad_user.script_path IS
    'scriptPath (logon script): normally a name relative to the NETLOGON share, or a UNC path. '
    'NULL = not set (or collected before adprofiler 0.8.0). (schema v44)';

-- SYSVOL script commands (scripts.ini / psscripts.ini) become a fourth
-- source of gpo_setting_edge rows.
ALTER TABLE ad_intel.gpo_setting_edge
    DROP CONSTRAINT IF EXISTS gpo_setting_edge_source_check;
ALTER TABLE ad_intel.gpo_setting_edge
    ADD CONSTRAINT gpo_setting_edge_source_check
    CHECK (source IN ('security_template', 'registry', 'audit', 'scripts'));
COMMENT ON TABLE ad_intel.gpo_setting_edge IS
    'One Group Policy setting defined in a GPO''s SYSVOL folder. '
    'source ''security_template'': GptTmpl.inf; section = INI section ([System Access], '
    '[Kerberos Policy], [Event Audit], [Privilege Rights], [Group Membership], '
    '[Service General Setting], ...), setting_key = the INI key, setting_value = the raw value '
    '(e.g. Privilege Rights "*S-1-5-32-544,*S-1-5-32-551"). '
    'source ''registry'': Registry.pol and GptTmpl [Registry Values]; section = ''HKLM'' or '
    '''HKCU'', setting_key = ''<key path>\<value name>'' without the hive (e.g. '
    '''System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity''), value_type = '
    'REG_DWORD / REG_SZ / REG_MULTI_SZ / REG_EXPAND_SZ / REG_QWORD / REG_BINARY / DELETE, '
    'setting_value = decimal for DWORD/QWORD, text for strings (multi-strings joined with '
    'newline), hex for binary. '
    'source ''audit'': audit.csv; section = ''advanced_audit'', setting_key = the subcategory GUID '
    '(lowercase, no braces), value_type = the subcategory name, setting_value = Setting Value '
    '(0 none, 1 success, 2 failure, 3 both). '
    'source ''scripts'' (schema v44): scripts.ini / psscripts.ini in Machine\Scripts or '
    'User\Scripts; section = Startup / Shutdown / Logon / Logoff, setting_key = '
    '''scripts.ini:<n>'' or ''psscripts.ini:<n>'' (the script''s index), value_type = ''script'' or '
    '''powershell'', setting_value = CmdLine (a bare name means the GPO''s own Scripts folder). '
    'Parameters are not stored (they can carry credentials). '
    'Values whose name suggests a credential are stored as ''<redacted>''. Compare keys '
    'case-insensitively. (schema v39, v44)';
COMMENT ON COLUMN ad_intel.gpo_preference_item_edge.preference_type IS
    'Groups, ScheduledTasks, Services, DataSources, Drives, Printers; Files and FolderOptions '
    'from schema v44 (sysvol_collector 1.1). details_json: for Files {from_path, target_path}; '
    'for FolderOptions {properties: the Properties attributes, children: [{tag, attributes}]}. '
    '(schema v44)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (44, 'dSHeuristics string, msDS-Other-Settings and NetBIOS name on ad_domain; '
            'ad_user.script_path; gpo_setting_edge source scripts; Files / FolderOptions '
            'preference types')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
