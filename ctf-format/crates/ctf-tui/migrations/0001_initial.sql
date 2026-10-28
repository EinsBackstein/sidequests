-- Phase 5 schema: the platform's durable ingest state.
--
-- Plain SQL, no ORM and no operator awareness. The deployment may be a
-- CloudNativePG cluster, a local `docker run postgres:17`, or anything else that
-- speaks the Postgres wire protocol; nothing below assumes which.
--
-- Derived data only. A `.ctf` bundle remains the source of truth; every column
-- here either points at committed bytes or records an operator action about them.

CREATE TABLE challenges (
    id          BIGSERIAL PRIMARY KEY,
    slug        TEXT NOT NULL,
    version     BIGINT NOT NULL CHECK (version >= 0),
    name        TEXT NOT NULL,
    category    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (slug, version)
);

-- The challenge list groups by slug, so the lookup is by slug first.
CREATE INDEX challenges_slug_idx ON challenges (slug);

CREATE TABLE bundles (
    id              BIGSERIAL PRIMARY KEY,
    challenge_id    BIGINT NOT NULL REFERENCES challenges (id) ON DELETE CASCADE,
    total_len       BIGINT NOT NULL CHECK (total_len >= 0),
    -- The whole-file digest names the exact bytes an ingest verdict is about.
    sha256          BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    commitment_root BYTEA NOT NULL CHECK (octet_length(commitment_root) = 32),
    suite_id        INTEGER NOT NULL CHECK (suite_id >= 0),
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Where the operator read it from, for the audit trail. Not authoritative:
    -- the bytes column is what a re-inspection or a release reads.
    source_path     TEXT,
    -- The bundle itself. Inline payloads are in the file by definition; an
    -- EXTERNAL section's bytes are not, so this is bounded by what the author
    -- chose to embed rather than by the size of a forensics image.
    bytes           BYTEA NOT NULL
);

CREATE INDEX bundles_challenge_idx ON bundles (challenge_id, ingested_at DESC);
CREATE INDEX bundles_sha256_idx ON bundles (sha256);

CREATE TABLE sections (
    id              BIGSERIAL PRIMARY KEY,
    bundle_id       BIGINT NOT NULL REFERENCES bundles (id) ON DELETE CASCADE,
    name_id         INTEGER NOT NULL CHECK (name_id >= 0),
    name            TEXT NOT NULL DEFAULT '',
    kind            INTEGER NOT NULL,
    flags           INTEGER NOT NULL,
    comp            INTEGER NOT NULL,
    enc             INTEGER NOT NULL,
    len_plain       BIGINT NOT NULL CHECK (len_plain >= 0),
    len_stored      BIGINT NOT NULL CHECK (len_stored >= 0),
    -- Named `byte_offset`, not `offset`: OFFSET is reserved in Postgres.
    byte_offset     BIGINT NOT NULL CHECK (byte_offset >= 0),
    root            BYTEA NOT NULL CHECK (octet_length(root) = 32),
    chunk_size      BIGINT NOT NULL CHECK (chunk_size >= 0),
    chunk_index_off BIGINT NOT NULL CHECK (chunk_index_off >= 0),
    -- The serving rule's first check: an explicit allowlist column. Kept
    -- denormalized next to `flags` so a reader that only looks at columns cannot
    -- accidentally read `NOT sealed` as "serve it".
    player_visible  BOOLEAN NOT NULL,
    sealed          BOOLEAN NOT NULL,
    external        BOOLEAN NOT NULL,
    UNIQUE (bundle_id, name_id)
);

CREATE INDEX sections_bundle_idx ON sections (bundle_id, name_id);
-- The serving query is the narrow one: visible, not sealed, one bundle.
CREATE INDEX sections_serving_idx ON sections (bundle_id) WHERE player_visible AND NOT sealed;

CREATE TABLE verification (
    id          BIGSERIAL PRIMARY KEY,
    bundle_id   BIGINT NOT NULL REFERENCES bundles (id) ON DELETE CASCADE,
    -- Tri-state plus the parse-time rejection that never gets a bundle row.
    status      TEXT NOT NULL CHECK (status IN ('passed', 'unverified', 'failed', 'rejected')),
    reason      TEXT NOT NULL,
    -- The `ctf/verification/v1` record from `ctf-generator` when a gate ran, and
    -- null when it did not. JSONB because the record is derived data the platform
    -- reads, not a column set this schema owns.
    gate        JSONB,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX verification_bundle_idx ON verification (bundle_id, checked_at DESC);
CREATE INDEX verification_status_idx ON verification (status, checked_at DESC);

CREATE TABLE entitlements (
    subject     TEXT NOT NULL,
    seq         BIGINT NOT NULL CHECK (seq >= 0),
    record      JSONB NOT NULL,
    prev_hash   BYTEA,
    hash        BYTEA NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subject, seq)
);

CREATE INDEX entitlements_subject_idx ON entitlements (subject, seq DESC);

CREATE TABLE audit_log (
    id      BIGSERIAL PRIMARY KEY,
    at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    detail  JSONB NOT NULL
);

CREATE INDEX audit_log_at_idx ON audit_log (at DESC, id DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action, at DESC);
