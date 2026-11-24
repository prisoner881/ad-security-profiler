-- ============================================================================
-- schema_migration_v51.sql -- every e-mail address, on both sides, and the
-- links between Entra ID accounts and AD user accounts
-- adprofiler: full-rescan
-- ============================================================================
--
-- entra_graph_collector.py 1.0.8 and adprofiler.py 1.0.11 collect more of the
-- addresses an account carries, and the collector links more Entra accounts
-- to their AD account:
--
--   entra_user (snapshot table, refreshed every collection):
--     other_mails                      otherMails: alternate addresses (for a
--                                      guest, the address it was invited with)
--     im_addresses                     imAddresses: Teams / SIP addresses
--     identities                       identities[]: sign-in identities
--                                      (signInType, issuer, issuerAssignedId);
--                                      a guest's or external user's sign-in
--                                      address is here
--     on_premises_user_principal_name  the UPN as it is in AD (differs from
--                                      the cloud UPN when the AD UPN suffix is
--                                      not a verified domain)
--     on_premises_immutable_id         the sync source anchor (normally the
--                                      AD objectGUID or mS-DS-ConsistencyGuid,
--                                      base64)
--     on_premises_sam_account_name,    where a synced account came from, also
--     on_premises_domain_name          when that domain was not collected
--     on_prem_match_method             how on_prem_object_guid was found:
--                                      'sid' (onPremisesSecurityIdentifier =
--                                      objectSid) or 'immutable_id'
--                                      (onPremisesImmutableId decodes to the
--                                      AD objectGUID); NULL = no exact link
--
--   ad_user (versioned):
--     other_mailbox                    otherMailbox: alternate addresses
--     target_address                   targetAddress: the address mail is
--                                      routed to (Exchange hybrid: the
--                                      ...mail.onmicrosoft.com address)
--
--   Views:
--     v_ad_user_address                every address of every current AD user,
--                                      one row per (user, address, source)
--     v_entra_user_address             the same for every Entra user
--     v_entra_ad_address_match         LIKELY links: an Entra account with no
--                                      exact link to AD that shares an address
--                                      with an AD user. A shared address is
--                                      not proof that the accounts belong to
--                                      the same person, so these are kept
--                                      apart from on_prem_object_guid, which
--                                      stays an exact link only.
--
-- The new ad_user columns are filled when an object is next read, so this
-- migration asks for one adprofiler.py run with --full-rescan. The Entra
-- columns are filled by the next entra_graph_collector.py run.
-- ============================================================================

BEGIN;

SET search_path TO ad_intel, public;

ALTER TABLE ad_intel.entra_user
    ADD COLUMN IF NOT EXISTS other_mails text[],
    ADD COLUMN IF NOT EXISTS im_addresses text[],
    ADD COLUMN IF NOT EXISTS identities jsonb,
    ADD COLUMN IF NOT EXISTS on_premises_user_principal_name text,
    ADD COLUMN IF NOT EXISTS on_premises_immutable_id text,
    ADD COLUMN IF NOT EXISTS on_premises_sam_account_name text,
    ADD COLUMN IF NOT EXISTS on_premises_domain_name text,
    ADD COLUMN IF NOT EXISTS on_prem_match_method text;

ALTER TABLE ad_intel.entra_user DROP CONSTRAINT IF EXISTS entra_user_on_prem_match_method_check;
ALTER TABLE ad_intel.entra_user ADD CONSTRAINT entra_user_on_prem_match_method_check
    CHECK (on_prem_match_method IS NULL OR on_prem_match_method IN ('sid', 'immutable_id'));

COMMENT ON COLUMN ad_intel.entra_user.other_mails IS
    'Graph otherMails: alternate e-mail addresses (a guest''s invitation address; often a '
    'personal address). (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.im_addresses IS
    'Graph imAddresses: instant-messaging (Teams / SIP) addresses, as Graph returns them. (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.identities IS
    'Graph identities[]: JSONB array of {signInType, issuer, issuerAssignedId}. A guest''s or '
    'external user''s sign-in address is an issuerAssignedId here. (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.on_premises_user_principal_name IS
    'Graph onPremisesUserPrincipalName: the UPN in AD of a synced account. (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.on_premises_immutable_id IS
    'Graph onPremisesImmutableId: the sync source anchor, base64 (normally the AD objectGUID '
    'or mS-DS-ConsistencyGuid). (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.on_premises_sam_account_name IS
    'Graph onPremisesSamAccountName of a synced account. (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.on_premises_domain_name IS
    'Graph onPremisesDomainName (DNS name of the AD domain) of a synced account. (schema v51)';
COMMENT ON COLUMN ad_intel.entra_user.on_prem_match_method IS
    'How on_prem_object_guid was found: ''sid'' (onPremisesSecurityIdentifier = '
    'directory_object.object_sid) or ''immutable_id'' (onPremisesImmutableId decodes to '
    'directory_object.object_guid). NULL with on_prem_object_guid NULL: no exact link; see '
    'v_entra_ad_address_match for likely links. (schema v51)';

ALTER TABLE ad_intel.ad_user
    ADD COLUMN IF NOT EXISTS other_mailbox text[],
    ADD COLUMN IF NOT EXISTS target_address text;

COMMENT ON COLUMN ad_intel.ad_user.other_mailbox IS
    'otherMailbox: alternate e-mail addresses. (schema v51)';
COMMENT ON COLUMN ad_intel.ad_user.target_address IS
    'targetAddress (Exchange schema): the address mail for the user is routed to, with its '
    'type prefix (e.g. SMTP:jdoe@contoso.mail.onmicrosoft.com). NULL when not set or the '
    'Exchange schema is absent. (schema v51)';

-- ---------------------------------------------------------------------------
-- Addresses. A value counts as an e-mail address when it looks like
-- local@domain.tld after the type prefix is removed; proxyAddresses entries
-- of other types (X500:, SIP:, EUM:, ...) are not e-mail addresses. Guest
-- UPNs (...#EXT#@tenant.onmicrosoft.com) are left out: they are not
-- deliverable, and the guest's real address is in mail / otherMails /
-- identities.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW ad_intel.v_ad_user_address AS
WITH src AS (
    SELECT u.client_id, u.object_guid, u.mail AS raw, 'AD mail'::text AS source
      FROM ad_intel.ad_user u
     WHERE u.valid_to IS NULL AND u.mail IS NOT NULL
    UNION ALL
    SELECT u.client_id, u.object_guid, substring(pa FROM 6),
           CASE WHEN pa LIKE 'SMTP:%' THEN 'AD proxyAddresses (primary)'
                ELSE 'AD proxyAddresses (alias)' END
      FROM ad_intel.ad_user u
     CROSS JOIN LATERAL unnest(u.proxy_addresses) AS pa
     WHERE u.valid_to IS NULL AND pa ILIKE 'smtp:%'
    UNION ALL
    SELECT u.client_id, u.object_guid, om, 'AD otherMailbox'
      FROM ad_intel.ad_user u
     CROSS JOIN LATERAL unnest(u.other_mailbox) AS om
     WHERE u.valid_to IS NULL
    UNION ALL
    SELECT u.client_id, u.object_guid, regexp_replace(u.target_address, '^smtp:', '', 'i'),
           'AD targetAddress'
      FROM ad_intel.ad_user u
     WHERE u.valid_to IS NULL AND u.target_address IS NOT NULL
       -- SMTP: prefix, or no type prefix at all (X400:, X500: ... are not e-mail)
       AND (u.target_address ILIKE 'smtp:%' OR u.target_address !~ '^[A-Za-z0-9]+:')
    UNION ALL
    SELECT u.client_id, u.object_guid, u.user_principal_name, 'AD userPrincipalName'
      FROM ad_intel.ad_user u
     WHERE u.valid_to IS NULL AND u.user_principal_name IS NOT NULL
)
SELECT s.client_id, s.object_guid, btrim(s.raw) AS address, lower(btrim(s.raw)) AS address_lc, s.source
  FROM src s
 WHERE btrim(s.raw) ~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$';

COMMENT ON VIEW ad_intel.v_ad_user_address IS
    'Every e-mail address of every current AD user: mail, SMTP proxyAddresses (primary / '
    'alias), otherMailbox, an SMTP targetAddress and the userPrincipalName. One row per '
    '(user, address, source); address_lc is the lower-cased form to match on. (schema v51)';

CREATE OR REPLACE VIEW ad_intel.v_entra_user_address AS
WITH src AS (
    SELECT u.client_id, u.entra_object_id, u.mail AS raw, 'Entra mail'::text AS source
      FROM ad_intel.entra_user u
     WHERE u.mail IS NOT NULL
    UNION ALL
    SELECT u.client_id, u.entra_object_id, substring(pa FROM 6),
           CASE WHEN pa LIKE 'SMTP:%' THEN 'Entra proxyAddresses (primary)'
                ELSE 'Entra proxyAddresses (alias)' END
      FROM ad_intel.entra_user u
     CROSS JOIN LATERAL unnest(u.proxy_addresses) AS pa
     WHERE pa ILIKE 'smtp:%'
    UNION ALL
    SELECT u.client_id, u.entra_object_id, om, 'Entra otherMails'
      FROM ad_intel.entra_user u
     CROSS JOIN LATERAL unnest(u.other_mails) AS om
    UNION ALL
    SELECT u.client_id, u.entra_object_id, regexp_replace(im, '^sip:', '', 'i'), 'Entra imAddresses'
      FROM ad_intel.entra_user u
     CROSS JOIN LATERAL unnest(u.im_addresses) AS im
    UNION ALL
    SELECT u.client_id, u.entra_object_id, i->>'issuerAssignedId', 'Entra sign-in identity'
      FROM ad_intel.entra_user u
     CROSS JOIN LATERAL jsonb_array_elements(
           CASE WHEN jsonb_typeof(u.identities) = 'array' THEN u.identities ELSE '[]'::jsonb END) AS i
     WHERE COALESCE(i->>'signInType', '') <> 'userPrincipalName'
    UNION ALL
    SELECT u.client_id, u.entra_object_id, u.user_principal_name, 'Entra userPrincipalName'
      FROM ad_intel.entra_user u
     WHERE u.user_principal_name IS NOT NULL
    UNION ALL
    SELECT u.client_id, u.entra_object_id, u.on_premises_user_principal_name,
           'Entra onPremisesUserPrincipalName'
      FROM ad_intel.entra_user u
     WHERE u.on_premises_user_principal_name IS NOT NULL
)
SELECT s.client_id, s.entra_object_id, btrim(s.raw) AS address, lower(btrim(s.raw)) AS address_lc, s.source
  FROM src s
 WHERE btrim(s.raw) ~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'
   AND btrim(s.raw) !~* '#ext#@';

COMMENT ON VIEW ad_intel.v_entra_user_address IS
    'Every e-mail address of every Entra user: mail, SMTP proxyAddresses (primary / alias), '
    'otherMails, imAddresses, sign-in identities (issuerAssignedId), userPrincipalName and '
    'onPremisesUserPrincipalName; guest #EXT# UPNs excluded. One row per (user, address, '
    'source). (schema v51)';

CREATE OR REPLACE VIEW ad_intel.v_entra_ad_address_match AS
SELECT e.client_id, e.entra_object_id, a.object_guid AS ad_object_guid, e.address_lc AS address,
       array_agg(DISTINCT e.source ORDER BY e.source) AS entra_sources,
       array_agg(DISTINCT a.source ORDER BY a.source) AS ad_sources
  FROM ad_intel.v_entra_user_address e
  JOIN ad_intel.entra_user eu
    ON eu.client_id = e.client_id AND eu.entra_object_id = e.entra_object_id
  JOIN ad_intel.v_ad_user_address a
    ON a.client_id = e.client_id AND a.address_lc = e.address_lc
 WHERE eu.on_prem_object_guid IS NULL
 GROUP BY e.client_id, e.entra_object_id, a.object_guid, e.address_lc;

COMMENT ON VIEW ad_intel.v_entra_ad_address_match IS
    'LIKELY links: an Entra user with no exact link to AD (on_prem_object_guid NULL: not '
    'synced, or synced from a domain that was not collected) that shares an e-mail address '
    'with a current AD user. One row per (Entra user, AD user, shared address), with the '
    'sources of the address on each side. A shared address suggests, but does not prove, '
    'that both accounts belong to the same person. (schema v51)';

INSERT INTO ad_intel.schema_migration_history (version_number, description) VALUES
    (51, 'Entra and AD e-mail address columns (otherMails, imAddresses, identities, on-premises '
         'UPN / immutable ID / sAMAccountName / domain, match method; AD otherMailbox, '
         'targetAddress) and the v_ad_user_address, v_entra_user_address and '
         'v_entra_ad_address_match views')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
