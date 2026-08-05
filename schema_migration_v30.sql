-- schema_migration_v30.sql
-- Adds ad_dns_zone, supporting plugin 4025 (AD-integrated DNS zone
-- nonsecure dynamic updates). Requires adprofiler.py v0.5.6 or later
-- to populate -- older collector versions will simply never write to
-- this table, which is harmless (the plugin correctly reports PASS
-- with zero rows until then, same as any other never-yet-populated
-- typed table in this schema).

SET search_path TO ad_intel, public;

CREATE TABLE ad_dns_zone (
    object_guid    UUID NOT NULL,
    client_id      UUID NOT NULL,
    version_id     BIGINT NOT NULL,
    valid_from     TIMESTAMPTZ NOT NULL,
    valid_to       TIMESTAMPTZ,
    zone_name      TEXT NOT NULL,
    allow_update   INTEGER,
    PRIMARY KEY (version_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    FOREIGN KEY (object_guid, client_id) REFERENCES directory_object(object_guid, client_id) ON DELETE RESTRICT
);
COMMENT ON COLUMN ad_dns_zone.allow_update IS
    'DSPROPERTY_ZONE_ALLOW_UPDATE per [MS-DNSP] 2.3.2.1.1 -- 0 = ZONE_UPDATE_OFF (no dynamic updates), '
    '1 = ZONE_UPDATE_UNSECURE (both secure and nonsecure updates allowed -- the concerning value), '
    '2 = ZONE_UPDATE_SECURE (secure updates only). NULL means the DSPROPERTY_ZONE_ALLOW_UPDATE '
    'entry was not found in this zone''s dNSProperty values at all.';
CREATE INDEX idx_ad_dns_zone_open ON ad_dns_zone (client_id, object_guid) WHERE valid_to IS NULL;
