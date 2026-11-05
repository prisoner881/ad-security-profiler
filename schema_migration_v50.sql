-- ============================================================================
-- schema_migration_v50.sql
--
-- check_scd2_integrity() works, and checks every history table
-- (adprofiler.py 1.0.9, adaudit.py 1.0.9, collector_daemon.py 1.0.2):
--
--   * It failed with "relation ... does not exist" for every caller: its
--     table names were not schema-qualified and it did not set its own
--     search_path. Names are now qualified and the search path is fixed.
--   * acl_edge's key now includes object_type_guid, as adprofiler.py's own
--     diff does: two ACEs that differ only in object type were reported as
--     duplicates.
--   * Every key now includes client_id (adprofiler.py diffs per client).
--   * It covers every table adprofiler.py keeps history in: before, 7 of
--     36. Now directory_object_version, the 21 typed object tables (one
--     open row per client and object_guid) and the 14 edge tables (one open
--     row per client and edge key).
--
-- Same signature and result columns; natural_key is now <client_id>:<key>.
-- No data change, no rescan needed.
-- ============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION ad_intel.check_scd2_integrity()
    RETURNS TABLE(source_table text, natural_key text, open_row_count bigint)
    LANGUAGE sql
    STABLE
    SET search_path = ad_intel, pg_temp
    AS $$
    SELECT 'directory_object_version', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.directory_object_version WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_adfs_dkm_object', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_adfs_dkm_object WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_cert_oid', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_cert_oid WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_cert_template', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_cert_template WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_computer', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_computer WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_display_specifier', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_display_specifier WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_dns_zone', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_dns_zone WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_domain', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_domain WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_enrollment_service', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_enrollment_service WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_fgpp', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_fgpp WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_foreign_security_principal', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_foreign_security_principal WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_gpo', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_gpo WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_group', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_group WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_kds_root_key', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_kds_root_key WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_ntauth_store', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_ntauth_store WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_ou', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_ou WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_pki_certificate_store', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_pki_certificate_store WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_schema_object', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_schema_object WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_site', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_site WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_subnet', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_subnet WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_trust', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_trust WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'ad_user', client_id::text || ':' || object_guid::text, count(*)
    FROM ad_intel.ad_user WHERE valid_to IS NULL
    GROUP BY client_id, object_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'acl_edge', client_id::text || ':' || concat_ws('/', coalesce(object_guid::text, '-'), coalesce(trustee_sid::text, '-'), coalesce(ace_type::text, '-'), coalesce(access_mask::text, '-'), coalesce(object_type_guid::text, '-')), count(*)
    FROM ad_intel.acl_edge WHERE valid_to IS NULL
    GROUP BY client_id, object_guid, trustee_sid, ace_type, access_mask, object_type_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'cert_template_enabled_edge', client_id::text || ':' || concat_ws('/', coalesce(ca_guid::text, '-'), coalesce(template_guid::text, '-')), count(*)
    FROM ad_intel.cert_template_enabled_edge WHERE valid_to IS NULL
    GROUP BY client_id, ca_guid, template_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'delegation_edge', client_id::text || ':' || concat_ws('/', coalesce(source_guid::text, '-'), coalesce(target_guid::text, '-'), coalesce(delegation_type::text, '-')), count(*)
    FROM ad_intel.delegation_edge WHERE valid_to IS NULL
    GROUP BY client_id, source_guid, target_guid, delegation_type HAVING count(*) > 1
    UNION ALL
    SELECT 'fgpp_applies_to_edge', client_id::text || ':' || concat_ws('/', coalesce(pso_guid::text, '-'), coalesce(target_guid::text, '-')), count(*)
    FROM ad_intel.fgpp_applies_to_edge WHERE valid_to IS NULL
    GROUP BY client_id, pso_guid, target_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'gmsa_password_reader_edge', client_id::text || ':' || concat_ws('/', coalesce(gmsa_guid::text, '-'), coalesce(trustee_sid::text, '-')), count(*)
    FROM ad_intel.gmsa_password_reader_edge WHERE valid_to IS NULL
    GROUP BY client_id, gmsa_guid, trustee_sid HAVING count(*) > 1
    UNION ALL
    SELECT 'gpo_link_edge', client_id::text || ':' || concat_ws('/', coalesce(container_guid::text, '-'), coalesce(gpo_guid::text, '-')), count(*)
    FROM ad_intel.gpo_link_edge WHERE valid_to IS NULL
    GROUP BY client_id, container_guid, gpo_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'gpo_preference_item_edge', client_id::text || ':' || concat_ws('/', coalesce(gpo_guid::text, '-'), coalesce(scope::text, '-'), coalesce(preference_type::text, '-'), coalesce(item_uid::text, '-')), count(*)
    FROM ad_intel.gpo_preference_item_edge WHERE valid_to IS NULL
    GROUP BY client_id, gpo_guid, scope, preference_type, item_uid HAVING count(*) > 1
    UNION ALL
    SELECT 'gpo_setting_edge', client_id::text || ':' || concat_ws('/', coalesce(gpo_guid::text, '-'), coalesce(scope::text, '-'), coalesce(source::text, '-'), coalesce(section::text, '-'), coalesce(setting_key::text, '-')), count(*)
    FROM ad_intel.gpo_setting_edge WHERE valid_to IS NULL
    GROUP BY client_id, gpo_guid, scope, source, section, setting_key HAVING count(*) > 1
    UNION ALL
    SELECT 'group_member_edge', client_id::text || ':' || concat_ws('/', coalesce(group_guid::text, '-'), coalesce(member_guid::text, '-')), count(*)
    FROM ad_intel.group_member_edge WHERE valid_to IS NULL
    GROUP BY client_id, group_guid, member_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'rbcd_unresolved_trustee_edge', client_id::text || ':' || concat_ws('/', coalesce(trustee_sid::text, '-'), coalesce(target_guid::text, '-')), count(*)
    FROM ad_intel.rbcd_unresolved_trustee_edge WHERE valid_to IS NULL
    GROUP BY client_id, trustee_sid, target_guid HAVING count(*) > 1
    UNION ALL
    SELECT 'rodc_prp_edge', client_id::text || ':' || concat_ws('/', coalesce(rodc_guid::text, '-'), coalesce(principal_guid::text, '-'), coalesce(relation::text, '-')), count(*)
    FROM ad_intel.rodc_prp_edge WHERE valid_to IS NULL
    GROUP BY client_id, rodc_guid, principal_guid, relation HAVING count(*) > 1
    UNION ALL
    SELECT 'spn_edge', client_id::text || ':' || concat_ws('/', coalesce(object_guid::text, '-'), coalesce(spn::text, '-')), count(*)
    FROM ad_intel.spn_edge WHERE valid_to IS NULL
    GROUP BY client_id, object_guid, spn HAVING count(*) > 1
    UNION ALL
    SELECT 'sysvol_script_edge', client_id::text || ':' || concat_ws('/', coalesce(share::text, '-'), coalesce(file_path::text, '-')), count(*)
    FROM ad_intel.sysvol_script_edge WHERE valid_to IS NULL
    GROUP BY client_id, share, file_path HAVING count(*) > 1
    UNION ALL
    SELECT 'unresolved_delegation_target_edge', client_id::text || ':' || concat_ws('/', coalesce(source_guid::text, '-'), coalesce(target_spn::text, '-')), count(*)
    FROM ad_intel.unresolved_delegation_target_edge WHERE valid_to IS NULL
    GROUP BY client_id, source_guid, target_spn HAVING count(*) > 1;
$$;

COMMENT ON FUNCTION ad_intel.check_scd2_integrity() IS
    'Returns every natural key with more than one currently open row (valid_to IS NULL) in a '
    'table adprofiler.py keeps history in: directory_object_version and the typed object tables '
    '(one open row per client and object_guid) and the edge tables (one open row per client and '
    'the key adprofiler.py diffs that table on). Should always return no rows; a row means a loader '
    'bug (a prior row not closed before a new one was opened). natural_key is <client_id>:<key>, '
    'a NULL key column shown as -. Callable from any search_path (schema v50); collector_daemon.py '
    'runs it after every collection run.';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (50, 'check_scd2_integrity(): schema-qualified with a fixed search_path, acl_edge key '
            'with object_type_guid, client_id in every key, all 36 history tables')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
