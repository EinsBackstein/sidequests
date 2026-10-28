//! DB-backed tests for the Postgres ingest pipeline and the serving rule.
//!
//! Gated on `CTF_TEST_DATABASE_URL`: without it every test returns early, so
//! `cargo test --workspace` stays green on a machine (and a CI runner) with no
//! Postgres. In CI the job sets the variable and these run.
//!
//! Each test creates its own schema, so they can run in parallel against one
//! database without truncating each other's rows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use ctf_format::cbor::Value;
use ctf_format::suite::suite;
use ctf_format::{Manifest, Recipient, SectionFlags, SectionKind, SectionSpec, write_bundle};
use ctf_tui::db;
use ctf_tui::ingest::{GateInputs, ingest};
use ctf_tui::model::{Progress, Stage, Status};

static SCHEMAS: AtomicU64 = AtomicU64::new(0);

fn database_url() -> Option<String> {
    match std::env::var("CTF_TEST_DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => None,
    }
}

async fn test_pool() -> Option<PgPool> {
    let url = database_url()?;
    let schema = format!(
        "ctf_tui_test_{}_{}",
        std::process::id(),
        SCHEMAS.fetch_add(1, Ordering::Relaxed)
    );
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to CTF_TEST_DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .expect("create test schema");
    // One connection in the pool, so every statement below sees this search_path.
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&pool)
        .await
        .expect("set search_path");
    db::migrate(&pool).await.expect("migrations apply");
    Some(pool)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors/conformance/golden")
        .join(name);
    std::fs::read(&path).expect("committed golden fixture")
}

#[tokio::test]
async fn migrations_apply_the_phase_five_schema() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
          WHERE table_schema = current_schema() ORDER BY table_name",
    )
    .fetch_all(&pool)
    .await
    .expect("read information_schema");
    let mut tables = Vec::new();
    for row in rows {
        use sqlx::Row;
        let name: String = row.try_get("table_name").expect("table_name");
        tables.push(name);
    }
    for expected in [
        "audit_log",
        "bundles",
        "challenges",
        "entitlements",
        "sections",
        "verification",
    ] {
        assert!(
            tables.iter().any(|table| table == expected),
            "missing table {expected}: {tables:?}"
        );
    }
}

#[tokio::test]
async fn minimal_ingest_stores_the_expected_rows_and_is_unverified() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let bytes = fixture("minimal.ctf");
    let mut events: Vec<Progress> = Vec::new();
    let outcome = ingest(&pool, &bytes, None, "test", |progress| {
        events.push(progress)
    })
    .await
    .expect("ingest");

    assert_eq!(outcome.status, Status::Unverified);
    assert_eq!(outcome.challenge.as_deref(), Some("whos-that-bird"));
    assert_eq!(outcome.version, Some(0));
    assert_eq!(outcome.sections, 1);
    let bundle_id = outcome.bundle_id.expect("a stored bundle");

    // Progress covers every stage, and the verify stage had real units.
    for stage in [Stage::Validate, Stage::Verify, Stage::Gate, Stage::Store] {
        assert!(
            events.iter().any(|event| event.stage == stage),
            "stage {stage:?} never reported: {events:?}"
        );
    }
    let verify_total = events
        .iter()
        .filter(|event| event.stage == Stage::Verify)
        .map(|event| event.total)
        .max()
        .unwrap_or(0);
    assert!(verify_total > 0, "verify reported no units: {events:?}");

    let challenges = db::challenges(&pool).await.expect("challenges");
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].slug, "whos-that-bird");
    assert_eq!(challenges[0].bundle_count, 1);
    assert_eq!(challenges[0].latest_status, Some(Status::Unverified));

    let sections = db::sections(&pool, bundle_id).await.expect("sections");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].kind, 1, "the only section is the manifest");
    assert!(!sections[0].player_visible);
    assert!(!sections[0].sealed);

    let verification = db::verification(&pool, bundle_id)
        .await
        .expect("verification query")
        .expect("a verification row");
    assert_eq!(verification.status, Status::Unverified);
    assert!(!verification.reason.is_empty());
    assert!(
        verification.gate.is_some(),
        "the §25.6 record is stored as JSONB"
    );

    let audit = db::audit_log(&pool, 20).await.expect("audit");
    assert!(
        audit.iter().any(|row| row.action == "ingest.stored"),
        "audit log must record the ingest: {audit:?}"
    );
}

#[tokio::test]
async fn demo_ingest_verifies_every_inline_chunk() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let bytes = fixture("demo.ctf");
    let mut events: Vec<Progress> = Vec::new();
    let outcome = ingest(&pool, &bytes, None, "test", |progress| {
        events.push(progress)
    })
    .await
    .expect("ingest");

    assert_eq!(outcome.status, Status::Unverified);
    assert_eq!(outcome.challenge.as_deref(), Some("workstation-triage"));
    assert_eq!(outcome.version, Some(3));
    // manifest, the inline notes artifact, and the external image.
    assert_eq!(outcome.sections, 3);
    assert!(
        outcome.chunks_verified >= 3,
        "notes.md has three chunks: {}",
        outcome.chunks_verified
    );
    assert!(
        events.iter().any(|event| event.stage == Stage::Verify
            && event.done > 0
            && event.done < event.total),
        "the bar must advance through a multi-chunk bundle: {events:?}"
    );

    let bundle_id = outcome.bundle_id.expect("stored");
    let sections = db::sections(&pool, bundle_id).await.expect("sections");
    let notes = sections
        .iter()
        .find(|section| section.name == "notes.md")
        .expect("notes.md row");
    assert!(notes.player_visible);
    assert!(!notes.sealed);
    assert_eq!(notes.chunk_size, 4096);

    let served = db::served_artifacts(&pool, bundle_id)
        .await
        .expect("serving");
    // Both sections carry PLAYER_VISIBLE and neither is sealed, so both are
    // served. The external one is metadata only: its bytes are not in the
    // bundle, and the caller can see that from the EXTERNAL bit in `flags`.
    assert_eq!(served.len(), 2);
    let notes = served
        .iter()
        .find(|row| row.name == "notes.md")
        .expect("notes.md served");
    assert!(!SectionFlags(notes.flags as u16).external());
    let image = served
        .iter()
        .find(|row| row.name == "workstation.E01")
        .expect("the external artifact is player-visible");
    assert!(SectionFlags(image.flags as u16).external());
}

#[tokio::test]
async fn a_corrupt_byte_is_rejected_and_records_only_audit() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let mut bytes = fixture("minimal.ctf");
    // The manifest payload starts at 4096; flipping a byte there breaks its root
    // before any later rule can be blamed.
    if let Some(byte) = bytes.get_mut(4100) {
        *byte ^= 0xff;
    }
    let outcome = ingest(&pool, &bytes, None, "test", |_| {})
        .await
        .expect("ingest returns an outcome");
    assert_eq!(outcome.status, Status::Rejected);
    assert_eq!(outcome.bundle_id, None);

    let challenges = db::challenges(&pool).await.expect("challenges");
    assert!(challenges.is_empty(), "a rejection stores no challenge");
    let audit = db::audit_log(&pool, 20).await.expect("audit");
    assert!(
        audit.iter().any(|row| row.action == "ingest.rejected"),
        "a rejection is still audited: {audit:?}"
    );
}

#[tokio::test]
async fn a_gate_input_without_a_matching_document_stays_unverified() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let bytes = fixture("minimal.ctf");
    let missing = GateInputs::new("/nonexistent/challenge.yml", "00".repeat(32));
    let outcome = ingest(&pool, &bytes, Some(missing), "test", |_| {})
        .await
        .expect("ingest");
    assert_eq!(outcome.status, Status::Unverified);
    assert!(
        outcome.reason.contains("could not be read"),
        "reason names the failure: {}",
        outcome.reason
    );
}

#[tokio::test]
async fn the_sealed_and_player_visible_row_can_never_be_served() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    use sqlx::Row;

    let challenge = sqlx::query(
        "INSERT INTO challenges (slug, version, name, category) \
         VALUES ('poison', 1, 'Poison', 'test') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .expect("challenge");
    let challenge_id: i64 = challenge.try_get("id").expect("id");
    let bundle = sqlx::query(
        "INSERT INTO bundles \
            (challenge_id, total_len, sha256, commitment_root, suite_id, bytes) \
         VALUES ($1, 0, $2, $3, 1, $4) RETURNING id",
    )
    .bind(challenge_id)
    .bind(vec![0u8; 32])
    .bind(vec![0u8; 32])
    .bind(Vec::<u8>::new())
    .fetch_one(&pool)
    .await
    .expect("bundle");
    let bundle_id: i64 = bundle.try_get("id").expect("id");

    let insert = |name: &'static str, name_id: i32, flags: i32, visible: bool, sealed: bool| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO sections \
                    (bundle_id, name_id, name, kind, flags, comp, enc, len_plain, len_stored, \
                     byte_offset, root, chunk_size, chunk_index_off, player_visible, sealed, external) \
                 VALUES ($1, $2, $3, 2, $4, 0, 0, 1, 1, 0, $5, 0, 0, $6, $7, false)",
            )
            .bind(bundle_id)
            .bind(name_id)
            .bind(name)
            .bind(flags)
            .bind(vec![0u8; 32])
            .bind(visible)
            .bind(sealed)
            .execute(&pool)
            .await
            .expect("section");
        }
    };
    insert(
        "visible",
        1,
        SectionFlags::PLAYER_VISIBLE as i32,
        true,
        false,
    )
    .await;
    // The container makes this pair unrepresentable, but a manual UPDATE or a buggy
    // future writer could produce it. Both checks must drop it.
    insert(
        "poison-both",
        2,
        (SectionFlags::PLAYER_VISIBLE | SectionFlags::SEALED) as i32,
        true,
        true,
    )
    .await;
    // Columns claim visible, the bitfield says sealed-only: the second check is what
    // catches the disagreement.
    insert("poison-flags", 3, SectionFlags::SEALED as i32, true, false).await;

    let served = db::served_artifacts(&pool, bundle_id)
        .await
        .expect("serving query");
    let names: Vec<&str> = served.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["visible"],
        "only the allowlisted row may be served"
    );

    // The in-code check on its own, with no database involved.
    assert!(db::flags_allow_serving(SectionFlags::PLAYER_VISIBLE as i32));
    assert!(!db::flags_allow_serving(
        (SectionFlags::PLAYER_VISIBLE | SectionFlags::SEALED) as i32
    ));
    assert!(!db::flags_allow_serving(SectionFlags::SEALED as i32));
    assert!(!db::flags_allow_serving(0));
}

/// A sealed bundle with one `writeup`, declared for `event_end`.
fn sealed_bundle() -> (Vec<u8>, Vec<u8>) {
    let recipient = suite(1)
        .expect("suite 1")
        .kem()
        .expect("kem")
        .generate()
        .expect("keypair");
    let names = vec!["manifest", "writeup", "keys"];
    let declaration = Value::Map(vec![
        (
            Value::Text("release".into()),
            Value::Text("event_end".into()),
        ),
        (
            Value::Text("members".into()),
            Value::Array(vec![Value::Text("writeup".into())]),
        ),
    ]);
    let manifest = Manifest::build(
        "sealed-chal",
        "Sealed Challenge",
        &names,
        vec![(Value::Text("sealed".into()), declaration)],
    )
    .expect("manifest");
    let manifest_bytes = manifest.encode().expect("manifest bytes");
    let recipients = [Recipient {
        context: "seal",
        public_key: &recipient.public_key,
    }];
    let sections = vec![
        SectionSpec::inline(
            SectionKind::Manifest,
            0,
            SectionFlags::empty(),
            &manifest_bytes,
        ),
        SectionSpec::inline(
            SectionKind::Writeup,
            1,
            SectionFlags(SectionFlags::SEALED),
            b"the sealed writeup body",
        )
        .chunked(4096)
        .encrypted(&recipients),
        SectionSpec::envelopes(SectionKind::Keys, 2),
    ];
    let bytes = write_bundle(1, &sections).expect("write bundle");
    (bytes, recipient.secret_key)
}

#[tokio::test]
async fn audit_records_ingest_and_release_and_release_reports_the_member() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let (bytes, seal_key) = sealed_bundle();
    let outcome = ingest(&pool, &bytes, None, "test", |_| {})
        .await
        .expect("ingest sealed bundle");
    assert_eq!(outcome.status, Status::Unverified);
    let bundle_id = outcome.bundle_id.expect("stored");

    let release = ctf_tui::ingest::release(&pool, bundle_id, &seal_key, "test")
        .await
        .expect("release");
    assert_eq!(release.challenge, "sealed-chal");
    assert_eq!(release.release, "event_end");
    assert_eq!(release.members.len(), 1);
    assert_eq!(release.members[0].0, "writeup");
    assert_eq!(
        release.members[0].1,
        b"the sealed writeup body".len() as u64
    );

    let audit = db::audit_log(&pool, 50).await.expect("audit");
    assert!(
        audit.iter().any(|row| row.action == "ingest.stored"),
        "{audit:?}"
    );
    assert!(
        audit.iter().any(|row| row.action == "release.event_end"),
        "{audit:?}"
    );
}

#[tokio::test]
async fn entitlements_upsert_by_subject_and_seq() {
    let Some(pool) = test_pool().await else {
        eprintln!("skipping: CTF_TEST_DATABASE_URL is not set");
        return;
    };
    let first = json!({"type": "grant", "holder": "team-1"});
    db::upsert_entitlement(&pool, "team-1", 0, &first, None, &[1u8; 32])
        .await
        .expect("grant");
    let second = json!({"type": "transfer", "holder": "team-2"});
    db::upsert_entitlement(&pool, "team-1", 1, &second, Some(&[1u8; 32]), &[2u8; 32])
        .await
        .expect("transfer");

    // Re-delivery of the same sequence updates rather than appending a duplicate.
    let replayed = json!({"type": "transfer", "holder": "team-3"});
    db::upsert_entitlement(&pool, "team-1", 1, &replayed, Some(&[1u8; 32]), &[3u8; 32])
        .await
        .expect("replay");

    let rows = db::entitlements(&pool, 20).await.expect("query");
    assert_eq!(rows.len(), 2, "primary key (subject, seq) dedupes");
    let seq_one = rows.iter().find(|row| row.seq == 1).expect("seq 1");
    assert_eq!(seq_one.record["holder"], "team-3");
    assert_eq!(seq_one.hash, vec![3u8; 32]);
}
