-- 0001_mb_mirror: curated MusicBrainz mirror subset (CC0 core data).
--
-- What: minimal tables serving workers/mb lookup + trigram search.
-- Out of scope: the full 30+ table MusicBrainz schema.
-- Conventions: forward-only migration, uuid MBIDs, timestamptz audit cols.
-- Replication bookkeeping lives in mb_import_state (one row per packet).

CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Artists ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb_artist (
    mbid       UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    sort_name  TEXT NOT NULL DEFAULT '',
    type       TEXT,
    country    CHAR(2),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mb_artist_name_trgm_idx
    ON mb_artist USING gin (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS mb_artist_sort_name_trgm_idx
    ON mb_artist USING gin (sort_name gin_trgm_ops);

-- Releases --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb_release (
    mbid       UUID PRIMARY KEY,
    artist_mbid UUID REFERENCES mb_artist (mbid) ON DELETE SET NULL,
    title      TEXT NOT NULL,
    release_type TEXT,
    year       SMALLINT,
    caa_url    TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mb_release_artist_idx
    ON mb_release (artist_mbid);
CREATE INDEX IF NOT EXISTS mb_release_title_trgm_idx
    ON mb_release USING gin (title gin_trgm_ops);

-- Recordings ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mb_recording (
    mbid         UUID PRIMARY KEY,
    release_mbid UUID REFERENCES mb_release (mbid) ON DELETE SET NULL,
    title        TEXT NOT NULL,
    track_no     SMALLINT,
    duration_ms  INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS mb_recording_release_idx
    ON mb_recording (release_mbid);
CREATE INDEX IF NOT EXISTS mb_recording_title_trgm_idx
    ON mb_recording USING gin (title gin_trgm_ops);

-- Import / replication state -------------------------------------------
CREATE TABLE IF NOT EXISTS mb_import_state (
    id             SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_packet    INTEGER NOT NULL DEFAULT 0,
    last_applied_at TIMESTAMPTZ,
    lag_seconds    INTEGER,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO mb_import_state (id, last_packet)
    VALUES (1, 0)
    ON CONFLICT (id) DO NOTHING;
