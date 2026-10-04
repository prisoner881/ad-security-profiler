-- ============================================================================
-- schema_migration_v38.sql
--
-- Storage for data adprofiler.py 0.6.0 and entra_graph_collector.py 0.7.0
-- now collect, supporting plugins added in the advisory/compliance gap round
-- (1044-1051, 2035-2039, 3027-3029, 4031-4036, 5011-5017, 6011-6013,
-- 7007-7009, 9007, 10011-10019, 11009-11020). Run adprofiler.py once with
-- --full-rescan after applying it so existing objects get the new columns.
--
--   directory_object.sd_control
--       SECURITY_DESCRIPTOR_CONTROL flags of every object whose security
--       descriptor is read (SE_DACL_PROTECTED = 0x1000: inheritance
--       disabled). NULL = SD not read (plugin 5011).
--   ad_user / ad_computer.alt_security_identities
--       Explicit certificate mappings (altSecurityIdentities) -- ESC14 /
--       KB5014754 weak mappings (plugins 1046, 11019).
--   ad_user / ad_computer.cleartext_password_attributes
--       NAMES of the populated attributes among userPassword,
--       unixUserPassword, msSFU30Password and os400Password. The values are
--       never stored, here or in directory_object_version.attributes_full
--       (plugin 1044).
--   ad_user.account_expires
--       accountExpires; NULL = never expires (plugin 1048).
--   ad_user.assigned_authn_policy_silo / assigned_authn_policy
--       msDS-AssignedAuthNPolicySilo / msDS-AssignedAuthNPolicy DNs
--       (plugin 4036).
--   ad_computer.managed_by / krbtgt_link
--       managedBy and msDS-KrbTgtLink DNs (RODC checks, plugin 2037).
--   ad_computer.is_gmsa / is_dmsa / dmsa_preceded_by / dmsa_state
--       Managed service account class flags and the dMSA migration link
--       msDS-ManagedAccountPrecededByLink / msDS-DelegatedMSAState
--       (BadSuccessor, plugin 5017).
--   rodc_prp_edge
--       RODC password replication policy: principals in an RODC's
--       msDS-RevealedList ('revealed'), msDS-RevealOnDemandGroup
--       ('reveal_on_demand') and msDS-NeverRevealGroup ('never_reveal')
--       (plugin 2037).
--   ad_domain: recycle_bin_enabled, schema_object_version,
--       forest_updates_revision, domain_updates_revision,
--       smartcard_hash_rolling_enabled, kds_root_key_count,
--       laps_attribute_guids, authn_silos, authn_policy_count,
--       forest_root_dn (plugins 1050, 2038, 4031, 4033, 4034, 4036).
--   ad_backup_status
--       Last backup time per naming context (dSASignature originating
--       change time). Overwritten each run rather than versioned, because
--       it changes with every backup (plugin 4032).
--   ad_gpo.gpc_file_sys_path / gpo_flags
--       gPCFileSysPath and flags (1 = user settings disabled, 2 = computer
--       settings disabled) (plugins 9007, 11013). GPO security descriptors
--       now go to acl_edge and directory_object.owner_sid (plugin 5012).
--   ad_dns_zone.partition / has_wildcard_record / has_wpad_record
--       Forest-wide zones (ForestDnsZones) are now collected too; zone ACLs
--       go to acl_edge (plugin 4035).
--   ad_schema_object.default_security_descriptor / ldap_display_name
--       classSchema defaultSecurityDescriptor (SDDL) (plugin 5015).
--   ad_kds_root_key
--       KDS root keys (msKds-ProvRootKey) -- metadata only, never
--       msKds-RootKeyData; ACLs go to acl_edge (plugin 4034).
--   ad_adfs_dkm_object
--       Objects under CN=ADFS,CN=Microsoft,CN=Program Data -- the AD FS DKM
--       key containers; key material (thumbnailPhoto) is never read, only
--       whether the collector's own account could see it (plugin 5016).
--   ad_pki_certificate_store
--       CA certificates under CN=Certification Authorities and CN=AIA
--       (plugin 6013).
--   ad_enrollment_service.enrollment_servers / ca_certificates
--       msPKI-Enrollment-Servers (CES URIs) and the CA's own certificate
--       (plugins 6011, 6013).
--   ad_cert_template.minimal_key_size / private_key_flag
--       msPKI-Minimal-Key-Size / msPKI-Private-Key-Flag (plugin 6012).
--   ad_trust.supported_encryption_types
--       msDS-SupportedEncryptionTypes on the trusted domain object
--       (plugin 7007).
--   entra_directory_role_member.assignment_kind / assignment_start /
--       assignment_end
--       For active assignments: 'permanent', 'time_bound' or 'activated'
--       (PIM activation), from roleAssignmentScheduleInstances; NULL when
--       it couldn't be read (plugin 10012).
--   entra_security_posture.authorization_policy /
--       authorization_policy_status / role_schedule_status
--       Graph authorizationPolicy (user app registration/consent, guest
--       settings) and the status of the schedule read (plugins 10016,
--       10017). ca_policies now also stores each policy's conditions and
--       session controls (no column change).
--   control_evidence_fact.object_guid foreign key dropped
--       Findings about Entra objects and tenant-level findings carry an id
--       that is not an AD directory object; the constraint made those
--       plugins (10002, 10004-10007, 10011-10019, 11020) fail on their
--       evidence write whenever they reported something.
--   entra_role_assignment_history
--       First/last time each (role, member, assignment type) was seen,
--       kept across runs so new privileged assignments can be reported
--       (plugin 11020).
-- ============================================================================

BEGIN;

ALTER TABLE ad_intel.directory_object
    ADD COLUMN IF NOT EXISTS sd_control integer;
COMMENT ON COLUMN ad_intel.directory_object.sd_control IS
    'SECURITY_DESCRIPTOR_CONTROL flags from the last security descriptor read for this object '
    '(0x1000 SE_DACL_PROTECTED = DACL inheritance disabled; 0x0004 SE_DACL_PRESENT). NULL = the '
    'collector does not read this object''s security descriptor. (schema v38)';

ALTER TABLE ad_intel.ad_user
    ADD COLUMN IF NOT EXISTS alt_security_identities text[],
    ADD COLUMN IF NOT EXISTS cleartext_password_attributes text[],
    ADD COLUMN IF NOT EXISTS account_expires timestamptz,
    ADD COLUMN IF NOT EXISTS assigned_authn_policy_silo text,
    ADD COLUMN IF NOT EXISTS assigned_authn_policy text;
COMMENT ON COLUMN ad_intel.ad_user.alt_security_identities IS
    'altSecurityIdentities values (explicit certificate/Kerberos mappings, e.g. '
    '"X509:<I>issuer<SR>serial"). NULL/empty = none. (schema v38)';
COMMENT ON COLUMN ad_intel.ad_user.cleartext_password_attributes IS
    'Names of populated attributes among userPassword, unixUserPassword, msSFU30Password, '
    'os400Password. Values are never stored. Empty array = none populated; NULL = not collected '
    '(pre-v38 row). (schema v38)';
COMMENT ON COLUMN ad_intel.ad_user.account_expires IS
    'accountExpires as a timestamp; NULL = never expires (0 or 0x7FFFFFFFFFFFFFFF). (schema v38)';

ALTER TABLE ad_intel.ad_computer
    ADD COLUMN IF NOT EXISTS alt_security_identities text[],
    ADD COLUMN IF NOT EXISTS cleartext_password_attributes text[],
    ADD COLUMN IF NOT EXISTS managed_by text,
    ADD COLUMN IF NOT EXISTS krbtgt_link text,
    ADD COLUMN IF NOT EXISTS is_gmsa boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS is_dmsa boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS dmsa_preceded_by text,
    ADD COLUMN IF NOT EXISTS dmsa_state integer;
COMMENT ON COLUMN ad_intel.ad_computer.krbtgt_link IS
    'msDS-KrbTgtLink: DN of the RODC''s own krbtgt_NNNNN account (RODCs only). (schema v38)';
COMMENT ON COLUMN ad_intel.ad_computer.is_dmsa IS
    'objectClass includes msDS-DelegatedManagedServiceAccount (Windows Server 2025 dMSA). (schema v38)';
COMMENT ON COLUMN ad_intel.ad_computer.dmsa_preceded_by IS
    'msDS-ManagedAccountPrecededByLink: DN of the account this dMSA supersedes -- the dMSA '
    'inherits that account''s privileges (BadSuccessor, CVE-2025-53779). (schema v38)';

CREATE TABLE IF NOT EXISTS ad_intel.rodc_prp_edge (
    edge_id             BIGINT GENERATED ALWAYS AS IDENTITY,
    client_id           UUID NOT NULL,
    rodc_guid           UUID NOT NULL,
    principal_guid      UUID NOT NULL,
    relation            TEXT NOT NULL CHECK (relation IN ('revealed', 'reveal_on_demand', 'never_reveal')),
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    run_id_valid_from   BIGINT NOT NULL,
    run_id_valid_to     BIGINT,
    PRIMARY KEY (edge_id, valid_from),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (rodc_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (principal_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_from, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT,
    FOREIGN KEY (run_id_valid_to, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.rodc_prp_edge IS
    'RODC password replication policy. relation: ''revealed'' = principal_guid is in the RODC''s '
    'msDS-RevealedList (its secrets are cached on the RODC); ''reveal_on_demand'' = listed in '
    'msDS-RevealOnDemandGroup (allowed to be cached); ''never_reveal'' = listed in '
    'msDS-NeverRevealGroup (denied). Groups are stored as the group, not expanded. '
    'An RODC with no ''revealed'' edges may also be one whose msDS-RevealedList the collection '
    'account could not read. (schema v38)';
CREATE INDEX IF NOT EXISTS idx_rodc_prp_edge_open
    ON ad_intel.rodc_prp_edge (client_id, rodc_guid) WHERE valid_to IS NULL;

ALTER TABLE ad_intel.ad_domain
    ADD COLUMN IF NOT EXISTS recycle_bin_enabled boolean,
    ADD COLUMN IF NOT EXISTS schema_object_version integer,
    ADD COLUMN IF NOT EXISTS forest_updates_revision integer,
    ADD COLUMN IF NOT EXISTS domain_updates_revision integer,
    ADD COLUMN IF NOT EXISTS smartcard_hash_rolling_enabled boolean,
    ADD COLUMN IF NOT EXISTS kds_root_key_count integer,
    ADD COLUMN IF NOT EXISTS laps_attribute_guids jsonb,
    ADD COLUMN IF NOT EXISTS authn_silos jsonb,
    ADD COLUMN IF NOT EXISTS authn_policy_count integer,
    ADD COLUMN IF NOT EXISTS forest_root_dn text;
COMMENT ON COLUMN ad_intel.ad_domain.recycle_bin_enabled IS
    'AD Recycle Bin optional feature enabled (msDS-EnabledFeature on CN=Partitions references '
    'CN=Recycle Bin Feature). NULL = could not be read. (schema v38)';
COMMENT ON COLUMN ad_intel.ad_domain.schema_object_version IS
    'objectVersion of the schema NC head (e.g. 69 = 2012 R2, 87 = 2016, 88 = 2019/2022, '
    '91 = 2025). (schema v38)';
COMMENT ON COLUMN ad_intel.ad_domain.smartcard_hash_rolling_enabled IS
    'msDS-ExpirePasswordsOnSmartCardOnlyAccounts on the domain object (SCRIL NT hash rolling, '
    'DFL 2016+). NULL = attribute not in schema or unset. (schema v38)';
COMMENT ON COLUMN ad_intel.ad_domain.laps_attribute_guids IS
    'schemaIDGUID of each LAPS attribute present in this forest''s schema, as '
    '{"ms-Mcs-AdmPwd": "<guid>", "msLAPS-Password": "<guid>", "msLAPS-EncryptedPassword": "<guid>", '
    '"msLAPS-EncryptedDSRMPassword": "<guid>", ...}. Legacy LAPS GUIDs differ per forest. (schema v38)';
COMMENT ON COLUMN ad_intel.ad_domain.authn_silos IS
    'Authentication policy silos: [{name, dn, enforced, member_dns[], user_policy_dn, '
    'computer_policy_dn, service_policy_dn}]. Empty array = none defined. (schema v38)';
COMMENT ON COLUMN ad_intel.ad_domain.forest_root_dn IS
    'rootDomainNamingContext from RootDSE (forest root domain DN). (schema v38)';

CREATE TABLE IF NOT EXISTS ad_intel.ad_backup_status (
    client_id           UUID NOT NULL,
    naming_context      TEXT NOT NULL,
    last_backup_at      TIMESTAMPTZ,
    read_status         TEXT NOT NULL CHECK (read_status IN ('ok', 'never_backed_up', 'unreadable')),
    run_id              BIGINT NOT NULL,
    collected_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, naming_context),
    FOREIGN KEY (run_id, client_id) REFERENCES ad_intel.sync_run(run_id, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.ad_backup_status IS
    'Last backup per naming context: the originating-change time of dSASignature in the NC head''s '
    'msDS-ReplAttributeMetaData (updated by every backup made through the Windows backup API). '
    'One row per NC, overwritten every run (not versioned: it changes with each backup). '
    'read_status ''never_backed_up'' = dSASignature has never been changed after the NC was created. '
    '(schema v38)';

ALTER TABLE ad_intel.ad_gpo
    ADD COLUMN IF NOT EXISTS gpc_file_sys_path text,
    ADD COLUMN IF NOT EXISTS gpo_flags integer;
COMMENT ON COLUMN ad_intel.ad_gpo.gpo_flags IS
    'groupPolicyContainer flags: 0 = enabled, 1 = user settings disabled, 2 = computer settings '
    'disabled, 3 = all settings disabled. (schema v38)';

ALTER TABLE ad_intel.ad_dns_zone
    ADD COLUMN IF NOT EXISTS partition text,
    ADD COLUMN IF NOT EXISTS has_wildcard_record boolean,
    ADD COLUMN IF NOT EXISTS has_wpad_record boolean;
COMMENT ON COLUMN ad_intel.ad_dns_zone.partition IS
    '''DomainDnsZones'' or ''ForestDnsZones''. NULL on rows collected before v38 (DomainDnsZones). '
    '(schema v38)';

ALTER TABLE ad_intel.ad_schema_object
    ADD COLUMN IF NOT EXISTS default_security_descriptor text,
    ADD COLUMN IF NOT EXISTS ldap_display_name text;
COMMENT ON COLUMN ad_intel.ad_schema_object.default_security_descriptor IS
    'defaultSecurityDescriptor (SDDL) of a classSchema object: the DACL every new object of the '
    'class receives. (schema v38)';

CREATE TABLE IF NOT EXISTS ad_intel.ad_kds_root_key (
    object_guid     UUID NOT NULL,
    client_id       UUID NOT NULL,
    version_id      BIGINT NOT NULL,
    valid_from      TIMESTAMPTZ NOT NULL,
    valid_to        TIMESTAMPTZ,
    key_id          TEXT,
    create_time     TIMESTAMPTZ,
    use_start_time  TIMESTAMPTZ,
    PRIMARY KEY (version_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (object_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.ad_kds_root_key IS
    'KDS root keys (msKds-ProvRootKey under CN=Master Root Keys,CN=Group Key Distribution Service,'
    'CN=Services,<config>). Metadata only: msKds-RootKeyData is never read. Anyone who can read it '
    'can compute every gMSA password (Golden gMSA); ACLs are in acl_edge. (schema v38)';
CREATE INDEX IF NOT EXISTS idx_ad_kds_root_key_open ON ad_intel.ad_kds_root_key (client_id, object_guid) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS ad_intel.ad_adfs_dkm_object (
    object_guid                 UUID NOT NULL,
    client_id                   UUID NOT NULL,
    version_id                  BIGINT NOT NULL,
    valid_from                  TIMESTAMPTZ NOT NULL,
    valid_to                    TIMESTAMPTZ,
    object_class_name           TEXT,
    is_key_object               BOOLEAN NOT NULL DEFAULT false,
    key_readable_by_collector   BOOLEAN,
    PRIMARY KEY (version_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (object_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.ad_adfs_dkm_object IS
    'Objects under CN=ADFS,CN=Microsoft,CN=Program Data,<domain> (AD FS Distributed Key Manager). '
    'is_key_object = a contact object holding the DKM master key in thumbnailPhoto. The key itself '
    'is never read; key_readable_by_collector = the (low-privileged) collection account matched a '
    'presence filter on thumbnailPhoto, i.e. could read the key. ACLs are in acl_edge. (schema v38)';
CREATE INDEX IF NOT EXISTS idx_ad_adfs_dkm_object_open ON ad_intel.ad_adfs_dkm_object (client_id, object_guid) WHERE valid_to IS NULL;

CREATE TABLE IF NOT EXISTS ad_intel.ad_pki_certificate_store (
    object_guid         UUID NOT NULL,
    client_id           UUID NOT NULL,
    version_id          BIGINT NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_to            TIMESTAMPTZ,
    store               TEXT NOT NULL,
    ca_name             TEXT,
    certificates        JSONB DEFAULT '[]'::jsonb NOT NULL,
    certificate_count   INTEGER DEFAULT 0 NOT NULL,
    PRIMARY KEY (version_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (object_guid, client_id) REFERENCES ad_intel.directory_object(object_guid, client_id) ON DELETE RESTRICT
);
COMMENT ON TABLE ad_intel.ad_pki_certificate_store IS
    'certificationAuthority objects under CN=Certification Authorities (store = ''root'') and CN=AIA '
    '(store = ''aia''). certificates: parsed cACertificate entries, same shape as '
    'ad_ntauth_store.certificates: {subject_cn, issuer_cn, not_valid_before, not_valid_after, '
    'serial_number, thumbprint_sha1, key_algorithm, key_size, signature_hash_algorithm, '
    'parse_error}. (schema v38)';
CREATE INDEX IF NOT EXISTS idx_ad_pki_certificate_store_open ON ad_intel.ad_pki_certificate_store (client_id, object_guid) WHERE valid_to IS NULL;

ALTER TABLE ad_intel.ad_enrollment_service
    ADD COLUMN IF NOT EXISTS enrollment_servers text[],
    ADD COLUMN IF NOT EXISTS ca_certificates jsonb;
COMMENT ON COLUMN ad_intel.ad_enrollment_service.enrollment_servers IS
    'msPKI-Enrollment-Servers values (Certificate Enrollment Web Service URIs, each prefixed '
    '"<priority>\n<auth type>\n<renewal only>\n<uri>"). (schema v38)';
COMMENT ON COLUMN ad_intel.ad_enrollment_service.ca_certificates IS
    'Parsed cACertificate of the CA (same shape as ad_pki_certificate_store.certificates). (schema v38)';

ALTER TABLE ad_intel.ad_cert_template
    ADD COLUMN IF NOT EXISTS minimal_key_size integer,
    ADD COLUMN IF NOT EXISTS private_key_flag integer;
COMMENT ON COLUMN ad_intel.ad_cert_template.private_key_flag IS
    'msPKI-Private-Key-Flag (0x10 CT_FLAG_EXPORTABLE_KEY). (schema v38)';

ALTER TABLE ad_intel.ad_trust
    ADD COLUMN IF NOT EXISTS supported_encryption_types integer;
COMMENT ON COLUMN ad_intel.ad_trust.supported_encryption_types IS
    'msDS-SupportedEncryptionTypes on the trusted domain object; NULL = unset (RC4 only before '
    'the 2022 Kerberos hardening). (schema v38)';

ALTER TABLE ad_intel.entra_directory_role_member
    ADD COLUMN IF NOT EXISTS assignment_kind text,
    ADD COLUMN IF NOT EXISTS assignment_start timestamptz,
    ADD COLUMN IF NOT EXISTS assignment_end timestamptz;
COMMENT ON COLUMN ad_intel.entra_directory_role_member.assignment_kind IS
    'For assignment_type = ''active'': ''permanent'' (no end date), ''time_bound'' (assigned with an '
    'end date) or ''activated'' (a PIM-eligible user''s current activation), from '
    'roleAssignmentScheduleInstances. NULL = not determined (see '
    'entra_security_posture.role_schedule_status). (schema v38)';

ALTER TABLE ad_intel.entra_security_posture
    ADD COLUMN IF NOT EXISTS authorization_policy jsonb,
    ADD COLUMN IF NOT EXISTS authorization_policy_status text,
    ADD COLUMN IF NOT EXISTS role_schedule_status text;
COMMENT ON COLUMN ad_intel.entra_security_posture.authorization_policy IS
    'Graph /policies/authorizationPolicy: {allowInvitesFrom, guestUserRoleId, '
    'allowedToSignUpEmailBasedSubscriptions, allowEmailVerifiedUsersToJoinOrganization, '
    'blockMsolPowerShell, defaultUserRolePermissions: {allowedToCreateApps, '
    'allowedToCreateSecurityGroups, allowedToCreateTenants, allowedToReadOtherUsers, '
    'permissionGrantPoliciesAssigned[]}}. NULL = not read (see authorization_policy_status). '
    '(schema v38)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_role_assignment_history (
    client_id           UUID NOT NULL,
    role_template_id    UUID NOT NULL,
    role_display_name   TEXT,
    member_id           UUID NOT NULL,
    member_display_name TEXT,
    member_upn          TEXT,
    member_type         TEXT,
    assignment_type     TEXT NOT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, role_template_id, member_id, assignment_type)
);
COMMENT ON TABLE ad_intel.entra_role_assignment_history IS
    'Every (role, member, assignment type) entra_graph_collector.py has seen, with when it was '
    'first and last seen. Unlike entra_directory_role_member it is not replaced each run, so a '
    'newly granted assignment can be told apart from a long-standing one (plugin 11020). '
    'Group-held roles are recorded for the group''s members as well as the group. (schema v38)';

ALTER TABLE ad_intel.control_evidence_fact
    DROP CONSTRAINT IF EXISTS control_evidence_fact_object_guid_client_id_fkey;
COMMENT ON COLUMN ad_intel.control_evidence_fact.object_guid IS
    'The finding''s subject: an AD object''s objectGUID, an Entra object id, or a stable synthetic '
    'id (md5 of plugin/tenant keys) for tenant-level findings. Not a foreign key to '
    'directory_object since schema v38 -- Entra and tenant-level findings have no directory '
    'object, and the constraint made those plugins fail whenever they fired. (schema v38)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (38, 'Advisory/compliance gap round: certificate mappings, cleartext password attributes, '
            'RODC PRP, dMSA, GPO/DNS/KDS/ADFS ACLs, backups, Recycle Bin, schema version, '
            'PKI certificates, Entra role schedules, authorization policy and role history')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
