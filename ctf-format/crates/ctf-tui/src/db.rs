//! Every read and every generic write against Postgres.
//!
//! Every statement is checked at compile time by the `sqlx::query!` /
//! `query_as!` macros against the committed migrations, using the `.sqlx` offline
//! cache so a build needs no database. Rebuild that cache with
//! `cargo sqlx prepare --workspace` after changing a statement or the schema.
//!
//! There is no ORM, no query builder, and no schema knowledge anywhere else in the
//! crate. A column rename lands here and in `migrations/`, and nowhere else.
//!
//! Timestamps are selected as text (`checked_at::text`). The TUI only displays
//! them, and `timestamptz` already normalizes the instant, so pulling in `chrono`
//! or `time` solely to format a label would be a dependency with no behaviour.

use std::time::Duration;

use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};

use crate::model::{
    AuditRow, BundleRow, ChallengeRow, EntitlementRow, SectionRow, ServedRow, Status,
    VerificationRow, VerificationView,
};

/// A database or migration failure. The message goes to the TUI's error pane; it
/// never panics a render.
#[derive(Debug)]
pub enum DbError {
    Database(sqlx::Error),
    Migration(sqlx::migrate::MigrateError),
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database: {e}"),
            Self::Migration(e) => write!(f, "migration: {e}"),
        }
    }
}

impl core::error::Error for DbError {}

impl From<sqlx::Error> for DbError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}

impl From<sqlx::migrate::MigrateError> for DbError {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        Self::Migration(e)
    }
}

pub type DbResult<T> = Result<T, DbError>;

/// Connect and apply the committed migrations. The TUI's only startup order.
pub async fn connect(database_url: &str) -> DbResult<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

/// Apply `migrations/`, compiled into the binary by [`sqlx::migrate!`].
pub async fn migrate(pool: &PgPool) -> DbResult<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

/// The challenge list, one row per challenge version, newest bundles counted.
pub async fn challenges(pool: &PgPool) -> DbResult<Vec<ChallengeRow>> {
    let rows = sqlx::query!(
        "SELECT c.id, c.slug, c.version, c.name, c.category, \
                c.created_at::text AS \"created_at!\", c.updated_at::text AS \"updated_at!\", \
                COUNT(b.id)::bigint AS \"bundle_count!\", \
                (SELECT v.status FROM verification v \
                   JOIN bundles b2 ON b2.id = v.bundle_id \
                  WHERE b2.challenge_id = c.id \
                  ORDER BY v.checked_at DESC, v.id DESC LIMIT 1) AS latest_status, \
                (SELECT v.checked_at::text FROM verification v \
                   JOIN bundles b2 ON b2.id = v.bundle_id \
                  WHERE b2.challenge_id = c.id \
                  ORDER BY v.checked_at DESC, v.id DESC LIMIT 1) AS latest_at \
           FROM challenges c LEFT JOIN bundles b ON b.challenge_id = c.id \
          GROUP BY c.id \
          ORDER BY c.slug, c.version DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ChallengeRow {
            id: row.id,
            slug: row.slug,
            version: row.version,
            name: row.name,
            category: row.category,
            created_at: row.created_at,
            updated_at: row.updated_at,
            bundle_count: row.bundle_count,
            latest_status: row.latest_status.as_deref().and_then(Status::parse),
            latest_at: row.latest_at,
        })
        .collect())
}

/// Bundles for one challenge, newest first.
pub async fn bundles_for_challenge(pool: &PgPool, challenge_id: i64) -> DbResult<Vec<BundleRow>> {
    let rows = sqlx::query_as!(
        BundleRow,
        "SELECT id, challenge_id, total_len, sha256, commitment_root, suite_id, \
                ingested_at::text AS \"ingested_at!\", source_path \
           FROM bundles WHERE challenge_id = $1 \
          ORDER BY ingested_at DESC, id DESC",
        challenge_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// One bundle by id.
pub async fn bundle(pool: &PgPool, bundle_id: i64) -> DbResult<Option<BundleRow>> {
    let row = sqlx::query_as!(
        BundleRow,
        "SELECT id, challenge_id, total_len, sha256, commitment_root, suite_id, \
                ingested_at::text AS \"ingested_at!\", source_path \
           FROM bundles WHERE id = $1",
        bundle_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// The section table for the inspector.
pub async fn sections(pool: &PgPool, bundle_id: i64) -> DbResult<Vec<SectionRow>> {
    let rows = sqlx::query_as!(
        SectionRow,
        "SELECT id, bundle_id, name_id, name, kind, flags, comp, enc, len_plain, \
                len_stored, byte_offset AS \"offset\", root, chunk_size, chunk_index_off, \
                player_visible, sealed, external \
           FROM sections WHERE bundle_id = $1 ORDER BY name_id",
        bundle_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The latest verification row for one bundle.
pub async fn verification(pool: &PgPool, bundle_id: i64) -> DbResult<Option<VerificationRow>> {
    let row = sqlx::query!(
        "SELECT bundle_id, status, reason, gate, checked_at::text AS \"checked_at!\" \
           FROM verification WHERE bundle_id = $1 \
          ORDER BY checked_at DESC, id DESC LIMIT 1",
        bundle_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let status_text = row.status;
        VerificationRow {
            bundle_id: row.bundle_id,
            status: Status::parse(&status_text).unwrap_or(Status::Unverified),
            status_text,
            reason: row.reason,
            gate: row.gate,
            checked_at: row.checked_at,
        }
    }))
}

/// Every stored bundle's latest verdict, newest first.
pub async fn verification_list(pool: &PgPool) -> DbResult<Vec<VerificationView>> {
    let rows = sqlx::query!(
        "SELECT DISTINCT ON (b.id) b.id AS bundle_id, c.slug, c.version, v.status, \
                v.reason, v.checked_at::text AS \"checked_at!\" \
           FROM verification v \
           JOIN bundles b ON b.id = v.bundle_id \
           JOIN challenges c ON c.id = b.challenge_id \
          ORDER BY b.id, v.checked_at DESC, v.id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let status_text = row.status;
            VerificationView {
                bundle_id: row.bundle_id,
                slug: row.slug,
                version: row.version,
                status: Status::parse(&status_text).unwrap_or(Status::Unverified),
                status_text,
                reason: row.reason,
                checked_at: row.checked_at,
            }
        })
        .collect())
}

/// The audit log, newest first.
pub async fn audit_log(pool: &PgPool, limit: i64) -> DbResult<Vec<AuditRow>> {
    let rows = sqlx::query_as!(
        AuditRow,
        "SELECT id, at::text AS \"at!\", actor, action, detail \
           FROM audit_log ORDER BY at DESC, id DESC LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// The entitlement chain records, newest first.
pub async fn entitlements(pool: &PgPool, limit: i64) -> DbResult<Vec<EntitlementRow>> {
    let rows = sqlx::query_as!(
        EntitlementRow,
        "SELECT subject, seq, record, prev_hash, hash, recorded_at::text AS \"recorded_at!\" \
           FROM entitlements ORDER BY recorded_at DESC, subject, seq DESC LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Append one entitlement record. A replayed `(subject, seq)` is an upsert: the
/// chain is append-only by sequence, and the same sequence re-delivered must not
/// create a second row.
pub async fn upsert_entitlement(
    pool: &PgPool,
    subject: &str,
    seq: i64,
    record: &Value,
    prev_hash: Option<&[u8]>,
    hash: &[u8],
) -> DbResult<()> {
    sqlx::query!(
        "INSERT INTO entitlements (subject, seq, record, prev_hash, hash) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (subject, seq) DO UPDATE \
            SET record = EXCLUDED.record, \
                prev_hash = EXCLUDED.prev_hash, \
                hash = EXCLUDED.hash, \
                recorded_at = now()",
        subject,
        seq,
        record,
        prev_hash,
        hash,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Append one audit row on its own connection.
pub async fn record_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    detail: &Value,
) -> DbResult<()> {
    sqlx::query!(
        "INSERT INTO audit_log (actor, action, detail) VALUES ($1, $2, $3)",
        actor,
        action,
        detail,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Append one audit row inside an ingest transaction, so a stored bundle and the
/// record of storing it commit together.
pub async fn record_audit_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor: &str,
    action: &str,
    detail: &Value,
) -> DbResult<()> {
    sqlx::query!(
        "INSERT INTO audit_log (actor, action, detail) VALUES ($1, $2, $3)",
        actor,
        action,
        detail,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The raw bytes of a stored bundle, for the inspector and the release path.
pub async fn bundle_bytes(pool: &PgPool, bundle_id: i64) -> DbResult<Option<Vec<u8>>> {
    let bytes = sqlx::query_scalar!("SELECT bytes FROM bundles WHERE id = $1", bundle_id)
        .fetch_optional(pool)
        .await?;
    Ok(bytes)
}

/// The serving surface for one bundle.
///
/// Two independent checks, exactly as design §10 requires:
///
/// 1. **SQL allowlist.** `WHERE player_visible AND NOT sealed` — both columns are
///    written from the parsed record, and neither is derived as "not the other".
/// 2. **In-code flag check.** [`flags_allow_serving`] re-reads the raw `flags`
///    integer and requires `PLAYER_VISIBLE` *and* rejects `SEALED`. A row whose
///    columns disagree with its bitfield — a bug, a manual `UPDATE`, a future
///    writer — is dropped here even though the SQL admitted it.
///
/// Neither check is "everything except". A section missing from `sections`, or one
/// whose flags are zero, is not served.
pub async fn served_artifacts(pool: &PgPool, bundle_id: i64) -> DbResult<Vec<ServedRow>> {
    let rows = sqlx::query_as!(
        ServedRow,
        "SELECT name_id, name, len_plain, root, flags, player_visible, sealed \
           FROM sections \
          WHERE bundle_id = $1 AND player_visible AND NOT sealed \
          ORDER BY name_id",
        bundle_id,
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for candidate in rows {
        // The second, independent check. It reads only the bitfield, not the
        // columns the SQL above trusted.
        if flags_allow_serving(candidate.flags) {
            out.push(candidate);
        }
    }
    Ok(out)
}

/// Whether a raw section `flags` word permits serving: `PLAYER_VISIBLE` set and
/// `SEALED` clear.
///
/// This is the in-code half of the two-check serving rule and is exported so a test
/// can prove it rejects `SEALED|PLAYER_VISIBLE` without a database. It is an
/// allowlist: zero flags, `OPTIONAL`, `EXTERNAL`, or any future bit alone all fail.
pub fn flags_allow_serving(raw_flags: i32) -> bool {
    let Ok(bits) = u16::try_from(raw_flags) else {
        return false;
    };
    let flags = ctf_format::SectionFlags(bits);
    flags.player_visible() && !flags.sealed()
}
