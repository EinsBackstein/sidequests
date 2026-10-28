//! The ingest pipeline: validate → verify → offline gate → store.
//!
//! The order is not cosmetic. `Bundle::parse` is the §10 read path; the section
//! pass hashes what the file commits to; the gate runs only on bytes that parsed and
//! verified; and the transaction writes a bundle row only after all of that. A
//! parse or integrity failure is a [`Status::Rejected`] outcome plus an audit row,
//! never a partial bundle.
//!
//! # The one rule this module cannot relax
//!
//! A bundle is `passed` **only** when [`ctf_generator::offline_gate`] returned
//! `Passed` in this run. No gate input, a gate that could not be constructed, a
//! runtime-bearing challenge, a mismatched authoring document — every one of those
//! is `unverified` with the §25.6 reason. There is no branch here that upgrades an
//! unrun gate to a pass.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sqlx::PgPool;

use ctf_format::authoring::ChallengeDoc;
use ctf_format::cbor::Value as CborValue;
use ctf_format::chunk;
use ctf_format::{Bundle, Compression, Encryption, SectionKind, SectionRecord, policy};
use ctf_generator::{
    DeterminismDeclaration, DeterminismMode, GateStage, OfflineGate, UnverifiedReason,
    VerificationRecord,
};

use crate::db::{self, DbError, DbResult};
use crate::model::{Progress, Stage, Status};

/// The operator-supplied inputs that let the §25 offline gate run.
///
/// Both are needed. A document alone cannot derive the reference flag without the
/// event secret, and the secret alone does not say which modules to run.
#[derive(Debug, Clone)]
pub struct GateInputs {
    /// The authoring YAML the challenge was packed from.
    pub document: PathBuf,
    /// The event secret, 64 hex digits (32 bytes) by the CLI's contract.
    pub secret_hex: String,
    /// The reference subject. `reference` is the CLI's default.
    pub subject: String,
}

impl GateInputs {
    pub fn new(document: impl Into<PathBuf>, secret_hex: impl Into<String>) -> Self {
        Self {
            document: document.into(),
            secret_hex: secret_hex.into(),
            subject: "reference".to_owned(),
        }
    }
}

/// What one ingest established.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    pub status: Status,
    pub reason: String,
    /// `None` for a parse or integrity rejection: no bundle row exists to point at.
    pub bundle_id: Option<i64>,
    pub challenge: Option<String>,
    pub version: Option<u64>,
    pub sections: usize,
    pub chunks_verified: u64,
    pub policy_warnings: Vec<String>,
    /// The `ctf/verification/v1` record as stored, when one was built.
    pub gate: Option<Value>,
}

/// Run the whole pipeline and commit atomically.
///
/// `progress` is called synchronously from this task, in stage order, so the TUI can
/// repaint a [`ratatui::widgets::Gauge`](ratatui::widgets::Gauge) while a 40 GB
/// section pass is in flight. It must be cheap; the TUI's implementation is an
/// unbounded channel send.
pub async fn ingest<P>(
    pool: &PgPool,
    bytes: &[u8],
    gate: Option<GateInputs>,
    actor: &str,
    mut progress: P,
) -> DbResult<IngestOutcome>
where
    P: FnMut(Progress) + Send,
{
    let size = bytes.len() as u64;
    let sha256 = digest_sha256(bytes);
    progress(Progress {
        stage: Stage::Validate,
        done: 0,
        total: 1,
        label: format!("parsing {size} bytes"),
    });

    let bundle = match Bundle::parse(bytes) {
        Ok(bundle) => bundle,
        Err(e) => {
            let reason = format!("the bundle did not parse: {e}");
            record_rejection(pool, actor, &reason, bytes, &sha256, None).await?;
            return Ok(IngestOutcome {
                status: Status::Rejected,
                reason,
                bundle_id: None,
                challenge: None,
                version: None,
                sections: 0,
                chunks_verified: 0,
                policy_warnings: Vec::new(),
                gate: None,
            });
        }
    };
    progress(Progress {
        stage: Stage::Validate,
        done: 1,
        total: 1,
        label: "parsed".to_owned(),
    });

    let challenge = bundle.manifest.id().to_owned();
    let version = bundle.manifest.version();

    // Spec §29 policy pass. Diagnostics only, exactly like `ctf run`: the read-time
    // policy reports a tag or a third-party origin without changing what was stored.
    let mut warnings: Vec<String> = policy::check_manifest(&bundle.manifest)
        .into_iter()
        .map(|issue| format!("{}: {}", issue.key(), issue.message()))
        .collect();
    let descriptor = ctf_format::PlatformDescriptor::from_manifest(
        &bundle.manifest,
        ctf_format::DEFAULT_PLATFORM_NAMESPACE,
    );
    warnings.extend(
        descriptor
            .validate()
            .into_iter()
            .map(|issue| format!("descriptor {}: {}", issue.key(), issue.message())),
    );

    let section_total = bundle.sections.len() as u64;
    let chunk_total = chunk_count_of(&bundle);
    let verify_total = section_total.saturating_add(chunk_total);
    let mut done = 0u64;

    progress(Progress {
        stage: Stage::Verify,
        done,
        total: verify_total,
        label: format!("{section_total} sections, {chunk_total} chunks"),
    });

    let report = match bundle.verify_inline_sections_with_progress(|_sections_done, _total| {
        done = done.saturating_add(1);
        progress(Progress {
            stage: Stage::Verify,
            done,
            total: verify_total,
            label: "inline sections".to_owned(),
        });
    }) {
        Ok(report) => report,
        Err(e) => {
            let reason = format!("the section pass could not complete: {e}");
            record_rejection(pool, actor, &reason, bytes, &sha256, Some(&challenge)).await?;
            return Ok(rejected(&challenge, version, &reason, warnings));
        }
    };
    if !report.mismatches.is_empty() {
        let reason = format!(
            "section root mismatch for name_id {mismatches:?}",
            mismatches = report.mismatches
        );
        record_rejection(pool, actor, &reason, bytes, &sha256, Some(&challenge)).await?;
        return Ok(rejected(&challenge, version, &reason, warnings));
    }

    // Chunk indices (spec §9.3, §10 C1–C8). This is the pass a 40 GB ingest spends
    // its time in, so every chunk advances the bar. For an inline uncompressed
    // section the chunk plaintext is in the file and is checked against its chaining
    // value. For an `EXTERNAL` section the bytes are absent by design: the index is
    // still reduced to the committed root and every entry is bounds-checked, and the
    // bar advances per entry, but no bytes are fetched. A compressed or encrypted
    // inline section cannot yield per-chunk plaintext without a key or a codec this
    // pass is not allowed to invoke, so its index is checked and disclosed the same
    // way.
    let mut chunks_verified = 0u64;
    for record in &bundle.sections {
        if record.chunk_index_off == 0 || record.flags.sealed() || !record.kind.is_known() {
            continue;
        }
        let index = match bundle.chunk_index(record) {
            Ok(Some(index)) => index,
            Ok(None) => continue,
            Err(e) => {
                let reason = format!(
                    "chunk index for name_id {} does not reduce to its root: {e}",
                    record.name_id
                );
                record_rejection(pool, actor, &reason, bytes, &sha256, Some(&challenge)).await?;
                return Ok(rejected(&challenge, version, &reason, warnings));
            }
        };
        let count = chunk::chunk_count(record.len_plain, record.chunk_size).unwrap_or(0);
        let plain = plaintext_for_chunking(&bundle, record);
        let chunk_size = usize::try_from(record.chunk_size).unwrap_or(0);
        let mut index_in_range = 0u64;
        while index_in_range < count {
            if let Some(plain) = plain.as_deref()
                && chunk_size != 0
            {
                let start = usize::try_from(index_in_range)
                    .ok()
                    .and_then(|i| i.checked_mul(chunk_size));
                let end = start
                    .and_then(|s| s.checked_add(chunk_size))
                    .map(|e| e.min(plain.len()));
                if let (Some(start), Some(end)) = (start, end)
                    && let Some(chunk_bytes) = plain.get(start..end)
                {
                    if let Err(e) = index.verify_chunk(index_in_range, chunk_bytes) {
                        let reason = format!(
                            "chunk {index_in_range} of name_id {} failed verification: {e}",
                            record.name_id
                        );
                        record_rejection(pool, actor, &reason, bytes, &sha256, Some(&challenge))
                            .await?;
                        return Ok(rejected(&challenge, version, &reason, warnings));
                    }
                    chunks_verified = chunks_verified.saturating_add(1);
                }
            }
            index_in_range = index_in_range.saturating_add(1);
            done = done.saturating_add(1);
            progress(Progress {
                stage: Stage::Verify,
                done,
                total: verify_total,
                label: format!("chunks of name_id {}", record.name_id),
            });
        }
    }

    progress(Progress {
        stage: Stage::Gate,
        done: 0,
        total: 1,
        label: "offline gate".to_owned(),
    });
    let record = match gate {
        Some(inputs) => gate_record(&bundle, &inputs),
        None => unverified_without_inputs(&bundle),
    };
    let status: Status = record.status.into();
    let gate_json = record.to_json().parse::<Value>().ok();
    progress(Progress {
        stage: Stage::Gate,
        done: 1,
        total: 1,
        label: status.as_str().to_owned(),
    });

    // One transaction: the challenge/bundle/section/verification rows and the audit
    // row commit together. A failure at any step leaves no half-ingested bundle.
    let mut tx = pool.begin().await?;
    let challenge_id: i64 = sqlx::query_scalar!(
        "INSERT INTO challenges (slug, version, name, category) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (slug, version) DO UPDATE \
            SET name = EXCLUDED.name, category = EXCLUDED.category, updated_at = now() \
         RETURNING id",
        challenge,
        i64::try_from(version).unwrap_or(i64::MAX),
        bundle.manifest.name(),
        bundle.manifest.category(),
    )
    .fetch_one(&mut *tx)
    .await?;

    let bundle_id: i64 = sqlx::query_scalar!(
        "INSERT INTO bundles \
            (challenge_id, total_len, sha256, commitment_root, suite_id, source_path, bytes) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id",
        challenge_id,
        i64::try_from(size).unwrap_or(i64::MAX),
        sha256.as_slice(),
        bundle.footer.root.as_slice(),
        i32::from(bundle.header.suite_id),
        Option::<String>::None,
        bytes,
    )
    .fetch_one(&mut *tx)
    .await?;

    let section_total = bundle.sections.len() as u64;
    for (position, record) in bundle.sections.iter().enumerate() {
        let name = bundle.manifest.name_of(record.name_id).unwrap_or("");
        sqlx::query!(
            "INSERT INTO sections \
                (bundle_id, name_id, name, kind, flags, comp, enc, len_plain, len_stored, \
                 byte_offset, root, chunk_size, chunk_index_off, player_visible, sealed, external) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
            bundle_id,
            i32::from(record.name_id),
            name,
            i32::from(record.kind.to_u16()),
            i32::from(record.flags.0),
            i32::from(record.comp as u8),
            i32::from(record.enc as u8),
            i64::try_from(record.len_plain).unwrap_or(i64::MAX),
            i64::try_from(record.len_stored).unwrap_or(i64::MAX),
            i64::try_from(record.offset).unwrap_or(i64::MAX),
            record.root.as_slice(),
            i64::from(record.chunk_size),
            i64::try_from(record.chunk_index_off).unwrap_or(i64::MAX),
            record.flags.player_visible(),
            record.flags.sealed(),
            record.flags.external(),
        )
        .execute(&mut *tx)
        .await?;
        let done = (position as u64).saturating_add(1);
        progress(Progress {
            stage: Stage::Store,
            done,
            total: section_total.saturating_add(2),
            label: format!("section {}/{}", done, section_total),
        });
    }

    sqlx::query!(
        "INSERT INTO verification (bundle_id, status, reason, gate) VALUES ($1, $2, $3, $4)",
        bundle_id,
        status.as_str(),
        record.reason,
        gate_json.clone(),
    )
    .execute(&mut *tx)
    .await?;

    let audit_detail = json!({
        "schema": "ctf/audit/ingest/v1",
        "bundle_id": bundle_id,
        "challenge": challenge,
        "version": version,
        "size": size,
        "sha256": crate::model::hex(&sha256),
        "commitment_root": crate::model::hex(&bundle.footer.root),
        "sections": bundle.sections.len(),
        "chunks_verified": chunks_verified,
        "status": status.as_str(),
        "reason": &record.reason,
        "policy_warnings": &warnings,
    });
    db::record_audit_in_tx(&mut tx, actor, "ingest.stored", &audit_detail).await?;

    progress(Progress {
        stage: Stage::Store,
        done: section_total.saturating_add(2),
        total: section_total.saturating_add(2),
        label: "committed".to_owned(),
    });

    tx.commit().await?;

    Ok(IngestOutcome {
        status,
        reason: record.reason,
        bundle_id: Some(bundle_id),
        challenge: Some(challenge),
        version: Some(version),
        sections: bundle.sections.len(),
        chunks_verified,
        policy_warnings: warnings,
        gate: gate_json,
    })
}

/// A rejected outcome with no bundle row. Shared by the parse and integrity paths.
fn rejected(challenge: &str, version: u64, reason: &str, warnings: Vec<String>) -> IngestOutcome {
    IngestOutcome {
        status: Status::Rejected,
        reason: reason.to_owned(),
        bundle_id: None,
        challenge: Some(challenge.to_owned()),
        version: Some(version),
        sections: 0,
        chunks_verified: 0,
        policy_warnings: warnings,
        gate: None,
    }
}

/// Record a rejection. There is deliberately no bundle row: the file did not earn
/// one, and a row would make it look ingestible to every later query.
async fn record_rejection(
    pool: &PgPool,
    actor: &str,
    reason: &str,
    bytes: &[u8],
    sha256: &[u8],
    challenge: Option<&str>,
) -> DbResult<()> {
    let detail = json!({
        "schema": "ctf/audit/ingest-rejected/v1",
        "status": Status::Rejected.as_str(),
        "reason": reason,
        "size": bytes.len(),
        "sha256": crate::model::hex(sha256),
        "challenge": challenge,
    });
    db::record_audit(pool, actor, "ingest.rejected", &detail).await?;
    Ok(())
}

/// The plaintext this pass may split into chunks, if any.
///
/// Only an inline, uncompressed, unencrypted section exposes its chunks directly.
/// An `EXTERNAL` section has no bytes here; a compressed or encrypted one would need
/// a codec or key. `None` still advances the bar — the index was reduced and its
/// entries are bounds-checked — but it is never counted in `chunks_verified`.
fn plaintext_for_chunking(bundle: &Bundle<'_>, record: &SectionRecord) -> Option<Vec<u8>> {
    if record.flags.external() || record.comp != Compression::None || record.enc != Encryption::None
    {
        return None;
    }
    bundle
        .section_bytes(record)
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Chunks the §10 index pass will walk, for the progress denominator.
fn chunk_count_of(bundle: &Bundle<'_>) -> u64 {
    let mut total = 0u64;
    for record in &bundle.sections {
        if record.chunk_index_off == 0 || record.flags.sealed() || !record.kind.is_known() {
            continue;
        }
        if let Ok(count) = chunk::chunk_count(record.len_plain, record.chunk_size) {
            total = total.saturating_add(count);
        }
    }
    total
}

/// The §25.6 record for a run where the operator supplied no gate inputs.
///
/// It is never `passed`; the most it can say is why it could not gate.
fn unverified_without_inputs(bundle: &Bundle<'_>) -> VerificationRecord {
    let generate = bundle.manifest.declaration("generate");
    let declares_generator = generate
        .and_then(|generate| generate.get("wasm"))
        .and_then(CborValue::as_text)
        .is_some();
    let declares_solver = bundle
        .manifest
        .declaration("verify")
        .and_then(|verify| verify.get("solver"))
        .and_then(CborValue::as_text)
        .is_some();
    let offline_declared = bundle
        .manifest
        .declaration("verify")
        .and_then(|verify| verify.get("offline"))
        .is_some_and(|offline| matches!(offline, CborValue::Bool(true)));

    let reason = if bundle.manifest.declaration("runtime").is_some() {
        UnverifiedReason::RuntimeDeclared.to_string()
    } else if !declares_generator {
        UnverifiedReason::NoGenerator.to_string()
    } else if !declares_solver {
        UnverifiedReason::NoSolver.to_string()
    } else if !offline_declared {
        UnverifiedReason::OfflineNotDeclared.to_string()
    } else {
        "the offline gate was not requested: no authoring document and event secret were \
         supplied, so this ingest is unverified"
            .to_owned()
    };
    VerificationRecord {
        challenge: bundle.manifest.id().to_owned(),
        version: bundle.manifest.version(),
        subject: "reference".to_owned(),
        status: ctf_generator::GateStatus::Unverified,
        reason,
        generator_root: None,
        cross_engine: None,
        runs: None,
    }
}

/// Build the §25.6 record from the operator's inputs.
///
/// Every failure to construct the gate is `unverified`, not `failed` and never
/// `passed`: the bundle is intact but no gate ran. A gate that starts and fails a
/// §25.5 stage is `failed`, matching `ctf run`.
fn gate_record(bundle: &Bundle<'_>, inputs: &GateInputs) -> VerificationRecord {
    let id = bundle.manifest.id();
    let version = bundle.manifest.version();
    let unverified = |reason: String| VerificationRecord {
        challenge: id.to_owned(),
        version,
        subject: inputs.subject.clone(),
        status: ctf_generator::GateStatus::Unverified,
        reason,
        generator_root: None,
        cross_engine: None,
        runs: None,
    };

    let text = match std::fs::read_to_string(&inputs.document) {
        Ok(text) => text,
        Err(_) => return unverified("the authoring document could not be read".to_owned()),
    };
    let doc = match ChallengeDoc::from_yaml(&text) {
        Ok(doc) => doc,
        Err(_) => return unverified("the authoring document was rejected".to_owned()),
    };
    if !doc.errors().is_empty() {
        return unverified("the authoring document failed schema validation".to_owned());
    }
    if doc.id != id || doc.version != version {
        return unverified(format!(
            "the authoring document describes `{}` version {}, not this bundle's `{id}` \
             version {version}",
            doc.id, doc.version
        ));
    }

    let secret = match hex_decode(&inputs.secret_hex) {
        Ok(secret) => secret,
        Err(e) => return unverified(format!("the event secret is not hex: {e}")),
    };
    if secret.len() != 32 {
        return unverified(format!(
            "the event secret must be 32 bytes (64 hex digits), got {}",
            secret.len()
        ));
    }
    let seed = match ctf_format::derive::subject_seed(&secret, id, version, &inputs.subject) {
        Ok(seed) => seed,
        Err(e) => return unverified(format!("the reference seed could not be derived: {e}")),
    };
    let expected_flag = ctf_format::derive::flag(&seed);

    let generate = bundle.manifest.declaration("generate");
    // G6/G7 from the bundle (§25.6): a version this build does not implement means
    // no stage can start, so the outcome is `unverified`, not `failed`.
    let interface = match bundle_declared_version(generate, "interface") {
        Ok(version) => version.unwrap_or(1),
        Err(()) => {
            return unverified(
                "the bundle's `generate.interface` is not an integer version".to_owned(),
            );
        }
    };
    let profile = match bundle_declared_version(generate, "profile") {
        Ok(version) => version.unwrap_or(1),
        Err(()) => {
            return unverified(
                "the bundle's `generate.profile` is not an integer version".to_owned(),
            );
        }
    };
    if let Err(version) = ctf_generator::abi::ensure_interface(interface) {
        return unverified(format!(
            "the bundle declares generator interface {version}, which this build does not implement"
        ));
    }
    if let Err(version) = ctf_generator::abi::ensure_profile(profile) {
        return unverified(format!(
            "the bundle declares WASM profile {version}, which this build does not implement"
        ));
    }

    let declared_generator = generate
        .and_then(|generate| generate.get("wasm"))
        .and_then(CborValue::as_text);
    let declared_solver = bundle
        .manifest
        .declaration("verify")
        .and_then(|verify| verify.get("solver"))
        .and_then(CborValue::as_text);

    let doc_dir = inputs.document.parent().unwrap_or_else(|| Path::new("."));
    let read_doc_module = |name: Option<&str>| -> Option<Vec<u8>> {
        let name = name?;
        std::fs::read(doc_dir.join(name)).ok()
    };
    let generator = match bundle_module(bundle, SectionKind::Generator, declared_generator) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) if declared_generator.is_some() => read_doc_module(declared_generator),
        Ok(None) => None,
        Err(_) => {
            return unverified("the bundle's generator section could not be read".to_owned());
        }
    };
    let solver = match bundle_module(bundle, SectionKind::Solver, declared_solver) {
        Ok(Some(bytes)) => Some(bytes),
        Ok(None) if declared_solver.is_some() => read_doc_module(declared_solver),
        Ok(None) => None,
        Err(_) => {
            return unverified("the bundle's solver section could not be read".to_owned());
        }
    };

    let determinism = match generate.and_then(|generate| generate.get("determinism")) {
        None => DeterminismDeclaration::Absent,
        Some(value) => match value.as_text().and_then(DeterminismMode::parse) {
            Some(mode) => DeterminismDeclaration::Mode(mode),
            None => DeterminismDeclaration::Unrecognized,
        },
    };
    let declared_outputs = generate
        .and_then(|generate| generate.get("outputs"))
        .and_then(CborValue::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|output| output.get("name").and_then(CborValue::as_text))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let report = ctf_generator::offline_gate(
        OfflineGate {
            generator: generator.as_deref(),
            solver: solver.as_deref(),
            seed: &seed,
            expected_flag: &expected_flag,
            runtime_declared: bundle.manifest.declaration("runtime").is_some(),
            offline_declared: bundle
                .manifest
                .declaration("verify")
                .and_then(|verify| verify.get("offline"))
                .is_some_and(|offline| matches!(offline, CborValue::Bool(true))),
            determinism,
            declared_outputs: &declared_outputs,
        },
        &ctf_generator::Limits::default(),
    );
    match report {
        Ok(report) => VerificationRecord::from_report(id, version, &inputs.subject, &report),
        Err(e) => {
            // A stage error can name a module path; the stored record carries the
            // stage and keeps any determinism summary, never the path (§25.6 S12).
            let determinism = e.determinism;
            VerificationRecord {
                challenge: id.to_owned(),
                version,
                subject: inputs.subject.clone(),
                status: ctf_generator::GateStatus::Failed,
                reason: format!(
                    "the offline gate could not complete a §25.5 stage ({})",
                    stage_name(e.stage)
                ),
                generator_root: determinism.map(|d| d.output_root),
                cross_engine: determinism.map(|d| d.cross_engine),
                runs: determinism.map(|d| d.runs),
            }
        }
    }
}

fn stage_name(stage: GateStage) -> &'static str {
    match stage {
        GateStage::Determinism => "determinism",
        GateStage::Solver => "solver",
    }
}

/// A bundle's `generate.interface`/`generate.profile` (§7.6). `Ok(None)` is absent,
/// which means version 1; `Err(())` is present but not a non-negative integer.
fn bundle_declared_version(generate: Option<&CborValue>, key: &str) -> Result<Option<u32>, ()> {
    match generate.and_then(|generate| generate.get(key)) {
        None => Ok(None),
        Some(value) => value
            .as_uint()
            .and_then(|version| u32::try_from(version).ok())
            .map(Some)
            .ok_or(()),
    }
}

/// The bytes of the module a bundle declares, verified against its root.
fn bundle_module(
    bundle: &Bundle<'_>,
    kind: SectionKind,
    declared: Option<&str>,
) -> Result<Option<Vec<u8>>, ctf_format::Error> {
    let Some(name) = declared else {
        return Ok(None);
    };
    let Some(name_id) = bundle
        .manifest
        .names()
        .iter()
        .position(|candidate| *candidate == name)
        .and_then(|index| u16::try_from(index).ok())
    else {
        return Ok(None);
    };
    let Some(record) = bundle
        .sections
        .iter()
        .find(|record| record.kind == kind && record.name_id == name_id)
    else {
        return Ok(None);
    };
    bundle
        .section_bytes(record)
        .map(|bytes| Some(bytes.into_owned()))
}

/// One release's audit-visible result. The plaintext is deliberately not carried:
/// the report names what was released, and the assets are the operator's to write.
#[derive(Debug, Clone)]
pub struct ReleaseOutcome {
    pub challenge: String,
    pub version: u64,
    pub release: String,
    pub members: Vec<(String, u64)>,
    pub report_json: Value,
}

/// Release a stored bundle's sealed sections with the offline seal key, then record
/// the release in the audit log.
pub async fn release(
    pool: &PgPool,
    bundle_id: i64,
    seal_secret_key: &[u8],
    actor: &str,
) -> Result<ReleaseOutcome, ReleaseError> {
    let bytes = db::bundle_bytes(pool, bundle_id)
        .await
        .map_err(ReleaseError::Db)?
        .ok_or(ReleaseError::MissingBundle(bundle_id))?;
    let bundle = Bundle::parse(&bytes).map_err(|e| ReleaseError::Format(e.to_string()))?;
    let release = ctf_format::release_at_event_end(&bundle, seal_secret_key)
        .map_err(|e| ReleaseError::Format(e.to_string()))?;
    let report_json: Value = release
        .report
        .to_json()
        .map_err(|e| ReleaseError::Format(e.to_string()))?
        .parse()
        .map_err(|e: serde_json::Error| ReleaseError::Format(e.to_string()))?;

    let detail = json!({
        "schema": "ctf/audit/release/v1",
        "bundle_id": bundle_id,
        "report": report_json,
    });
    db::record_audit(pool, actor, "release.event_end", &detail)
        .await
        .map_err(ReleaseError::Db)?;

    Ok(ReleaseOutcome {
        challenge: release.report.challenge_id,
        version: release.report.version,
        release: release.report.release,
        members: release
            .report
            .members
            .iter()
            .map(|member| (member.name.clone(), member.size))
            .collect(),
        report_json,
    })
}

/// Why a release did not happen.
#[derive(Debug)]
pub enum ReleaseError {
    Db(DbError),
    MissingBundle(i64),
    Format(String),
}

impl core::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "{e}"),
            Self::MissingBundle(id) => write!(f, "bundle {id} is not stored"),
            Self::Format(e) => write!(f, "release refused: {e}"),
        }
    }
}

impl core::error::Error for ReleaseError {}

/// Read a KEM key file: exactly one non-empty line of hex, the CLI's format.
pub fn read_key_file(path: &Path) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "a KEM key file has exactly one non-empty line of hex; found {}",
            lines.len()
        ));
    };
    hex_decode(line)
}

/// The whole-file digest, as 32 bytes.
fn digest_sha256(bytes: &[u8]) -> Vec<u8> {
    let text = ctf_format::oci::digest_sha256(bytes);
    hex_decode(text.strip_prefix("sha256:").unwrap_or(&text)).unwrap_or_default()
}

/// Decode lowercase or uppercase hex, rejecting an odd length or a bad digit.
fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!(
            "hex string has an odd number of digits ({})",
            bytes.len()
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0usize;
    while index < bytes.len() {
        let hi = bytes
            .get(index)
            .copied()
            .and_then(hex_nibble)
            .ok_or_else(|| "hex string contains a non-hex digit".to_owned())?;
        let lo = bytes
            .get(index.saturating_add(1))
            .copied()
            .and_then(hex_nibble)
            .ok_or_else(|| "hex string contains a non-hex digit".to_owned())?;
        out.push((hi << 4) | lo);
        index = index.saturating_add(2);
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
