-- ============================================================================
-- schema_migration_v39.sql
--
-- SYSVOL collection (adprofiler.py 0.7.0, --sysvol). Group Policy settings
-- live in the GPO's SYSVOL folder, not in LDAP: security templates
-- (GptTmpl.inf), administrative-template registry settings (Registry.pol),
-- advanced audit policy (audit.csv), Group Policy Preferences XML, and
-- logon/startup scripts. adprofiler.py reads them over SMB (read-only, with
-- the bind account) when run with --sysvol. Plugins 9008-9023 and 11021 use
-- them.
--
--   sysvol_collection_status
--       One row per client: when SYSVOL was last read, from which DC, and
--       how it went. No row = SYSVOL has never been collected, so plugins
--       that need it have nothing to evaluate (adaudit shows them as NOT
--       ASSESSED).
--   ad_gpo_sysvol
--       Per GPO, the outcome of reading its SYSVOL folder at the last
--       SYSVOL collection, plus gpt.ini's version (compared with the AD
--       versionNumber for plugin 9022). Overwritten each SYSVOL run.
--   gpo_setting_edge
--       One open row per (GPO, scope, source, section, key) setting.
--       source 'security_template' = GptTmpl.inf sections other than
--       [Registry Values]; 'registry' = Registry.pol entries and GptTmpl
--       [Registry Values] (normalized to hive-relative paths); 'audit' =
--       audit.csv subcategories. Values whose name suggests a secret
--       (password, pwd, secret, ...) are stored as '<redacted>'.
--       Versioned like other edges, so a changed setting is history.
--   gpo_preference_item_edge
--       Group Policy Preferences items of the types that can carry a
--       password (Groups, ScheduledTasks, Services, DataSources, Drives,
--       Printers) -- whether a cpassword is present (the value is never
--       stored), the account name it is for, and for local groups the
--       members added/removed.
--   sysvol_script_edge
--       Scripts in GPO script folders and the NETLOGON share containing
--       credential patterns: the pattern names and line numbers only,
--       never the matched text.
--   v_gpo_dc_application
--       Which GPOs apply to each domain controller and in what precedence
--       (1 = wins), resolved from gpo_link_edge, block inheritance,
--       enforcement, the GPO's "computer settings disabled" flag and its
--       security filtering (Apply Group Policy right). Site-linked GPOs
--       and WMI filters are not evaluated.
--   v_dc_effective_gpo_setting
--       The winning machine-scope value of every setting for each DC.
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ad_intel.sysvol_collection_status (
    client_id           UUID NOT NULL PRIMARY KEY,
    run_id              BIGINT NOT NULL,
    collected_at        TIMESTAMPTZ NOT NULL,
    smb_host            TEXT,
    status              TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'failed')),
    gpos_read           INTEGER NOT NULL DEFAULT 0,
    gpos_unreadable     INTEGER NOT NULL DEFAULT 0,
    netlogon_read       BOOLEAN,
    detail              TEXT,
    FOREIGN KEY (run_id, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.sysvol_collection_status IS
    'Outcome of the last SYSVOL collection (adprofiler.py --sysvol) for the client. ''failed'' = '
    'the share could not be read at all (no data changed); ''partial'' = some GPO folders or '
    'NETLOGON could not be read (their previous data is kept). No row = never collected. '
    '(schema v39)';

CREATE TABLE IF NOT EXISTS ad_intel.ad_gpo_sysvol (
    client_id           UUID NOT NULL,
    gpo_object_guid     UUID NOT NULL,
    sysvol_path         TEXT,
    read_status         TEXT NOT NULL CHECK (read_status IN ('ok', 'not_found', 'access_denied', 'error')),
    gpt_ini_version     INTEGER,
    files_read          TEXT[],
    error_detail        TEXT,
    run_id              BIGINT NOT NULL,
    collected_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, gpo_object_guid),
    FOREIGN KEY (gpo_object_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.ad_gpo_sysvol IS
    'Per GPO, the result of reading its SYSVOL folder at the last SYSVOL collection. read_status '
    '''not_found'' = no folder (orphaned GPC); ''access_denied'' = the bind account may not read it '
    '(typically security filtering that removed Authenticated Users); ''error'' = any other failure. '
    'For anything but ''ok'' the GPO''s previously collected settings are kept unchanged. '
    'gpt_ini_version = gpt.ini [General] Version (compare with ad_gpo.version_number). (schema v39)';

CREATE TABLE IF NOT EXISTS ad_intel.gpo_setting_edge (
    edge_id             BIGINT GENERATED ALWAYS AS IDENTITY,
    client_id           UUID NOT NULL,
    gpo_guid            UUID NOT NULL,
    scope               TEXT NOT NULL CHECK (scope IN ('machine', 'user')),
    source              TEXT NOT NULL CHECK (source IN ('security_template', 'registry', 'audit')),
    section             TEXT NOT NULL,
    setting_key         TEXT NOT NULL,
    value_type          TEXT,
    setting_value       TEXT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    run_id_valid_from   BIGINT NOT NULL,
    run_id_valid_to     BIGINT,
    PRIMARY KEY (edge_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (gpo_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_from, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_to, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
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
    'Values whose name suggests a credential are stored as ''<redacted>''. Compare keys '
    'case-insensitively. (schema v39)';
CREATE INDEX IF NOT EXISTS idx_gpo_setting_edge_open
    ON ad_intel.gpo_setting_edge (client_id, gpo_guid) WHERE valid_to IS NULL;
CREATE INDEX IF NOT EXISTS idx_gpo_setting_edge_key
    ON ad_intel.gpo_setting_edge (client_id, source, lower(setting_key)) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS ad_intel.gpo_preference_item_edge (
    edge_id             BIGINT GENERATED ALWAYS AS IDENTITY,
    client_id           UUID NOT NULL,
    gpo_guid            UUID NOT NULL,
    scope               TEXT NOT NULL CHECK (scope IN ('machine', 'user')),
    preference_type     TEXT NOT NULL,
    item_uid            TEXT NOT NULL,
    item_name           TEXT,
    action              TEXT,
    has_cpassword       BOOLEAN NOT NULL DEFAULT false,
    account_name        TEXT,
    details_json        TEXT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    run_id_valid_from   BIGINT NOT NULL,
    run_id_valid_to     BIGINT,
    PRIMARY KEY (edge_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (gpo_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_from, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_to, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.gpo_preference_item_edge IS
    'A Group Policy Preferences item (Machine|User\Preferences\<Type>\<Type>.xml) of type Groups, '
    'ScheduledTasks, Services, DataSources, Drives or Printers. has_cpassword = the item carries a '
    'cpassword (MS14-025: encrypted with a published AES key, so readable by every domain user); '
    'the value itself is never stored. account_name = the userName/runAs/accountName the password '
    'is for. action = C/R/U/D. details_json (canonical JSON text, cast with ::jsonb): for Groups '
    '{group_name, group_sid, delete_all_users, delete_all_groups, members: [{name, sid, action}]}; '
    'for ScheduledTasks {logon_type, run_level}. item_uid = the item''s uid attribute (or a hash '
    'of type+name when absent). (schema v39)';
CREATE INDEX IF NOT EXISTS idx_gpo_preference_item_edge_open
    ON ad_intel.gpo_preference_item_edge (client_id, gpo_guid) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS ad_intel.sysvol_script_edge (
    edge_id                 BIGINT GENERATED ALWAYS AS IDENTITY,
    client_id               UUID NOT NULL,
    share                   TEXT NOT NULL CHECK (share IN ('SYSVOL', 'NETLOGON')),
    file_path               TEXT NOT NULL,
    gpo_guid                UUID,
    size_bytes              BIGINT,
    credential_indicators   TEXT[] NOT NULL,
    valid_from              TIMESTAMPTZ NOT NULL,
    valid_to                TIMESTAMPTZ,
    run_id_valid_from       BIGINT NOT NULL,
    run_id_valid_to         BIGINT,
    PRIMARY KEY (edge_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (run_id_valid_from, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_to, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.sysvol_script_edge IS
    'A script or text file in a GPO''s Scripts folder (share SYSVOL, gpo_guid set) or on the '
    'NETLOGON share that contains credential patterns. credential_indicators = sorted '
    '"<pattern>:<line>" entries (e.g. "net_use_password:12", "plaintext_securestring:40"); the '
    'matched text is never stored. Only files with at least one indicator are recorded. '
    '(schema v39)';
CREATE INDEX IF NOT EXISTS idx_sysvol_script_edge_open
    ON ad_intel.sysvol_script_edge (client_id) WHERE valid_to IS NULL;

COMMENT ON COLUMN ad_intel.gpo_link_edge.link_order IS
    '1-based position of the link in the container''s gPLink attribute. gPLink lists links from '
    'lowest to highest precedence, so the LAST entry is GPMC''s "link order 1" and wins; '
    'v_gpo_dc_application converts this. (comment added in schema v39)';

CREATE OR REPLACE VIEW ad_intel.v_gpo_dc_application AS
WITH dc AS (
    SELECT c.client_id, c.object_guid AS dc_guid, lower(d.dn_current) AS dc_dn, d.object_sid AS dc_sid
    FROM ad_intel.ad_computer c
    JOIN ad_intel.directory_object d
      ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
    WHERE c.valid_to IS NULL AND c.is_domain_controller
),
som AS (
    SELECT o.client_id, o.object_guid, lower(d.dn_current) AS dn,
           COALESCE(o.block_inheritance, false) AS block_inheritance, false AS is_domain
    FROM ad_intel.ad_ou o
    JOIN ad_intel.directory_object d
      ON d.object_guid = o.object_guid AND d.client_id = o.client_id AND NOT d.is_deleted
    WHERE o.valid_to IS NULL
    UNION ALL
    SELECT m.client_id, m.object_guid, lower(d.dn_current),
           COALESCE(m.block_inheritance, false), true
    FROM ad_intel.ad_domain m
    JOIN ad_intel.directory_object d
      ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
    WHERE m.valid_to IS NULL
),
chain AS (
    -- Domain root and every OU above the DC. depth = number of commas in the
    -- container's DN (the domain root is the shallowest).
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid, s.object_guid AS container_guid, s.is_domain,
           s.block_inheritance,
           length(s.dn) - length(replace(s.dn, ',', '')) AS depth
    FROM dc
    JOIN som s ON s.client_id = dc.client_id AND dc.dc_dn LIKE '%,' || s.dn
),
blocked AS (
    -- Block inheritance on an OU stops non-enforced links from containers above it.
    SELECT client_id, dc_guid, max(depth) AS block_depth
    FROM chain WHERE block_inheritance AND NOT is_domain
    GROUP BY client_id, dc_guid
),
links AS (
    SELECT l.client_id, l.container_guid, l.gpo_guid, l.link_enforced, l.link_enabled,
           max(l.link_order) OVER (PARTITION BY l.client_id, l.container_guid) - l.link_order + 1
               AS gpmc_link_order
    FROM ad_intel.gpo_link_edge l
    WHERE l.valid_to IS NULL
),
dc_sids AS (
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid::text AS sid FROM dc WHERE dc.dc_sid IS NOT NULL
    UNION
    SELECT dc.client_id, dc.dc_guid, w.sid
    FROM dc CROSS JOIN (VALUES ('S-1-1-0'), ('S-1-5-11'), ('S-1-5-9')) AS w(sid)
    UNION
    SELECT dc.client_id, dc.dc_guid, gd.object_sid::text
    FROM dc
    JOIN ad_intel.v_effective_group_membership m
      ON m.client_id = dc.client_id AND m.member_guid = dc.dc_guid
    JOIN ad_intel.directory_object gd
      ON gd.object_guid = m.group_guid AND gd.client_id = m.client_id
    WHERE gd.object_sid IS NOT NULL
),
candidate AS (
    SELECT ch.client_id, ch.dc_guid, lk.gpo_guid, ch.container_guid, ch.is_domain, ch.depth,
           lk.link_enforced, lk.gpmc_link_order,
           (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0) AS computer_settings_enabled,
           (
             NOT EXISTS (
               SELECT 1 FROM ad_intel.acl_edge a
               JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
               WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                 AND a.ace_type = 'deny' AND a.inherit_only IS NOT TRUE
                 AND (a.access_mask & 256) <> 0
                 AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')
             )
             AND (
               NOT EXISTS (SELECT 1 FROM ad_intel.acl_edge a
                           WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid
                             AND a.valid_to IS NULL)
               OR EXISTS (
                 SELECT 1 FROM ad_intel.acl_edge a
                 JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
                 WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                   AND a.ace_type = 'allow' AND a.inherit_only IS NOT TRUE
                   AND ( ((a.access_mask & 256) <> 0
                          AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'))
                         OR (a.access_mask & 983551) = 983551
                         OR (a.access_mask & 268435456) <> 0 )
               )
             )
           ) AS security_filter_applies
    FROM chain ch
    JOIN links lk ON lk.client_id = ch.client_id AND lk.container_guid = ch.container_guid AND lk.link_enabled
    JOIN ad_intel.ad_gpo g ON g.object_guid = lk.gpo_guid AND g.client_id = lk.client_id AND g.valid_to IS NULL
    LEFT JOIN blocked b ON b.client_id = ch.client_id AND b.dc_guid = ch.dc_guid
    WHERE lk.link_enforced OR b.block_depth IS NULL OR ch.depth >= b.block_depth
)
SELECT c.client_id, c.dc_guid, c.gpo_guid, c.container_guid, c.is_domain AS linked_at_domain,
       c.depth, c.link_enforced, c.gpmc_link_order, c.computer_settings_enabled,
       c.security_filter_applies,
       CASE WHEN c.computer_settings_enabled AND c.security_filter_applies THEN
           row_number() OVER (
               PARTITION BY c.client_id, c.dc_guid
               ORDER BY (c.computer_settings_enabled AND c.security_filter_applies) DESC,
                        c.link_enforced DESC,
                        CASE WHEN c.link_enforced THEN c.depth END ASC,
                        CASE WHEN NOT c.link_enforced THEN c.depth END DESC,
                        c.gpmc_link_order ASC)
       END AS precedence
FROM candidate c;
COMMENT ON VIEW ad_intel.v_gpo_dc_application IS
    'GPOs linked (enabled link) to the domain root or an OU above each domain controller, with '
    'precedence (1 = highest; NULL = does not apply because computer settings are disabled or '
    'security filtering denies the DC the Apply Group Policy right). Order: enforced links first '
    '(higher container wins), then non-enforced links (deeper OU wins); within a container GPMC '
    'link order. Block inheritance removes non-enforced links above the blocking OU. Not '
    'evaluated: site-linked GPOs (a DC''s site is not collected), WMI filters, loopback. A GPO '
    'whose ACL was never collected is assumed to apply. (schema v39)';

CREATE OR REPLACE VIEW ad_intel.v_dc_effective_gpo_setting AS
SELECT DISTINCT ON (a.client_id, a.dc_guid, s.source, s.section, lower(s.setting_key))
       a.client_id, a.dc_guid, s.source, s.section, s.setting_key, s.value_type, s.setting_value,
       s.gpo_guid AS winning_gpo_guid, a.precedence, a.linked_at_domain
FROM ad_intel.v_gpo_dc_application a
JOIN ad_intel.gpo_setting_edge s
  ON s.client_id = a.client_id AND s.gpo_guid = a.gpo_guid AND s.valid_to IS NULL
 AND s.scope = 'machine'
WHERE a.precedence IS NOT NULL
ORDER BY a.client_id, a.dc_guid, s.source, s.section, lower(s.setting_key), a.precedence;
COMMENT ON VIEW ad_intel.v_dc_effective_gpo_setting IS
    'The winning machine-scope Group Policy value of each setting for each domain controller '
    '(from v_gpo_dc_application precedence). A setting no applying GPO defines is absent: it '
    'then has the OS default or a locally configured value, which is not visible. Account and '
    'Kerberos policy ([System Access] password/lockout keys, [Kerberos Policy]) only take effect '
    'from GPOs linked at the domain (linked_at_domain). (schema v39)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (39, 'SYSVOL collection: GPO settings, preferences, scripts, effective DC policy views')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
