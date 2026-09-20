//! The authoring surface: YAML in, a schema-checked document out.
//!
//! Normative: `spec/SPEC.md` §7.6 for the manifest keys these declarations
//! compile to, and design §10 for the authoring surface itself.
//!
//! # Why this rejects unknown keys, when the manifest does not
//!
//! The manifest's `crit` mechanism (spec §7.3) is *reader* forward
//! compatibility: an unknown key not named in `crit` is carried and ignored, which
//! is what lets the schema grow without breaking older readers. That is the right
//! behaviour for a reader and the wrong one for an author. A misspelled optional
//! key — `visibilty` for `visibility`, say — is carried, the value the author meant
//! to set is absent, and nothing at the container layer notices: exactly the
//! "silently publish a hidden challenge mid-event" incident design §10 names.
//!
//! The two mechanisms answer different questions, and this one answers "did the
//! author spell that right?". Every structure below therefore carries
//! `deny_unknown_fields`, so an unknown or misspelled key is a hard error at
//! authoring time, before a single byte is packed.
//!
//! # Errors name the key
//!
//! Authoring YAML is the author's own input, not a hostile byte stream, so unlike
//! the container's errors ([`crate::Error`]) these *do* echo the offending key.
//! Naming it is the whole point of the ticket; an error that said only "invalid
//! field" would leave the author hunting.

use core::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};

use crate::cbor::Value;
use crate::manifest::{check_id, check_name};

/// The highest authoring `spec` this build understands.
///
/// Independent of the container's `version_major.minor` and of
/// [`crate::manifest::MANIFEST_SPEC`], for the reasons spec §7.2 gives: the YAML
/// schema is its own thing.
pub const AUTHORING_SPEC: u64 = 1;

/// A parse or schema error from the authoring surface.
///
/// Carries the underlying diagnostic verbatim, which names the offending key
/// (serde's unknown-field message is "unknown field `…`"). See the module docs for
/// why echoing author input is correct here and not in [`crate::Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringError {
    message: String,
}

impl AuthoringError {
    fn from_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The diagnostic an author should read.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AuthoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for AuthoringError {}

/// A whole authoring document, as the YAML front end sees it.
///
/// Field names and nesting mirror design §10's example exactly. Unknown keys are
/// rejected at every level.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeDoc {
    /// Authoring schema version. Must be [`AUTHORING_SPEC`] or lower.
    pub spec: u64,
    /// Challenge identifier; the same shape the manifest enforces (spec §7.2).
    pub id: String,
    /// Challenge version. Absent means `0`.
    #[serde(default)]
    pub version: u64,
    /// Human-readable title.
    pub name: String,
    /// Challenge category.
    #[serde(default)]
    pub category: Option<String>,
    /// Markdown description.
    #[serde(default)]
    pub description: Option<String>,
    /// How the flag is derived. `flag: derived` is the one-word form.
    #[serde(default)]
    pub flag: Option<FlagSpec>,
    /// Generator declaration.
    #[serde(default)]
    pub generate: Option<GenerateSpec>,
    /// Runtime declaration.
    #[serde(default)]
    pub runtime: Option<RuntimeSpec>,
    /// Sealed-release declaration.
    #[serde(default)]
    pub sealed: Option<SealedSpec>,
    /// Solvability-gate declaration.
    #[serde(default)]
    pub verify: Option<VerifySpec>,
}

impl ChallengeDoc {
    /// Parse and strictly schema-check an authoring document.
    ///
    /// Unknown and misspelled keys are rejected at every nesting level, and the
    /// error names the key.
    pub fn from_yaml(yaml: &str) -> Result<Self, AuthoringError> {
        let doc: Self = serde_yaml_ng::from_str(yaml)
            .map_err(|e| AuthoringError::from_message(e.to_string()))?;
        if doc.spec > AUTHORING_SPEC {
            return Err(AuthoringError::from_message(format!(
                "authoring `spec` {} is newer than this build implements ({AUTHORING_SPEC})",
                doc.spec
            )));
        }
        Ok(doc)
    }

    /// The manifest keys this document declares, in no particular order.
    ///
    /// These are the later-phase keys of spec §7.6 — `flag`, `generate`,
    /// `runtime`, `sealed`, `verify` — plus `version`, `category`, and
    /// `description`. Each is emitted only when the author gave it, so an author
    /// who writes the minimal manifest-only challenge produces none.
    ///
    /// Cross-references this function cannot resolve — a section `name_id` for an
    /// external payload, the `names` table a generator's output names index — are
    /// `ctf pack`'s job (design §10, ticket 35), not the schema's.
    pub fn manifest_entries(&self) -> Vec<(Value, Value)> {
        let mut out = Vec::new();
        if self.version != 0 {
            out.push((text("version"), Value::Uint(self.version)));
        }
        if let Some(c) = &self.category {
            out.push((text("category"), Value::Text(c.clone())));
        }
        if let Some(d) = &self.description {
            out.push((text("description"), Value::Text(d.clone())));
        }
        if let Some(f) = &self.flag {
            out.push((text("flag"), f.to_cbor()));
        }
        if let Some(g) = &self.generate {
            out.push((text("generate"), g.to_cbor()));
        }
        if let Some(r) = &self.runtime {
            out.push((text("runtime"), r.to_cbor()));
        }
        if let Some(s) = &self.sealed {
            out.push((text("sealed"), s.to_cbor()));
        }
        if let Some(v) = &self.verify {
            out.push((text("verify"), v.to_cbor()));
        }
        out
    }
}

/// One finding from [`ChallengeDoc::validate`].
///
/// `key` is the dotted path of the offending key — `generate.determinism`,
/// `runtime.ports[0].protocol`, `sealed.members` — so an author knows exactly what to
/// fix. Authoring input is the author's own file, not a hostile byte stream, so this
/// names the key rather than restating the rule abstractly (spec §7.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    key: String,
    message: String,
}

impl ValidationIssue {
    fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }

    /// The dotted path of the offending key.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// What is wrong with it.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}`: {}", self.key, self.message)
    }
}

impl core::error::Error for ValidationIssue {}

/// One value from a fixed set, reported under its key when it is not one of them.
fn one_of(issues: &mut Vec<ValidationIssue>, key: &str, value: &str, allowed: &[&str]) {
    if !allowed.contains(&value) {
        issues.push(ValidationIssue::new(
            key,
            format!("must be one of {}", allowed.join(", ")),
        ));
    }
}

fn non_empty(issues: &mut Vec<ValidationIssue>, key: &str, value: &str) {
    if value.is_empty() {
        issues.push(ValidationIssue::new(key, "must not be empty"));
    }
}

/// `event_end`, `manual`, or `stage:<id>` with a non-empty id (spec §7.6).
fn valid_release(release: &str) -> bool {
    matches!(release, "event_end" | "manual")
        || release
            .strip_prefix("stage:")
            .is_some_and(|id| !id.is_empty())
}

impl ChallengeDoc {
    /// Check the values the typed schema cannot express, plus the policy rules that
    /// span keys.
    ///
    /// The schema itself (unknown keys, required keys, value types) is enforced by
    /// [`ChallengeDoc::from_yaml`] before this runs. What is left is *semantics*: an
    /// enum whose value is not one of its allowed names, an `id` or output name that
    /// violates the manifest's shape rules, and the serving policy that a section may
    /// not be both sealed and player-visible (spec §5.3, R5).
    ///
    /// An empty return means the document is valid and `ctf pack` will not be
    /// surprised by it.
    pub fn validate(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if check_id(&self.id).is_err() {
            issues.push(ValidationIssue::new(
                "id",
                "must be 1-64 bytes of lowercase ASCII letters, digits, and hyphens, \
                 and must not begin or end with a hyphen",
            ));
        }

        match &self.flag {
            Some(FlagSpec::Shorthand(s)) => non_empty(&mut issues, "flag", s),
            Some(FlagSpec::Detailed(d)) => {
                non_empty(&mut issues, "flag.derive", &d.derive);
                if let Some(scope) = &d.scope {
                    one_of(
                        &mut issues,
                        "flag.scope",
                        scope,
                        &["player", "team", "event"],
                    );
                }
            }
            None => {}
        }

        if let Some(g) = &self.generate {
            one_of(
                &mut issues,
                "generate.determinism",
                &g.determinism,
                &["strict", "flag_only", "none"],
            );
            let mut seen: Vec<&str> = Vec::new();
            for (i, output) in g.outputs.iter().enumerate() {
                let key = format!("generate.outputs[{i}].name");
                if let Some(reason) = check_name(&output.name) {
                    issues.push(ValidationIssue::new(key.clone(), reason));
                }
                if seen.contains(&output.name.as_str()) {
                    issues.push(ValidationIssue::new(key, "duplicate output name"));
                }
                seen.push(&output.name);
            }
        }

        if let Some(r) = &self.runtime {
            one_of(
                &mut issues,
                "runtime.instancing",
                &r.instancing,
                &["shared", "per_team"],
            );
            non_empty(&mut issues, "runtime.image", &r.image);
            non_empty(&mut issues, "runtime.ttl", &r.ttl);
            non_empty(&mut issues, "runtime.resources.cpu", &r.resources.cpu);
            non_empty(&mut issues, "runtime.resources.memory", &r.resources.memory);
            non_empty(
                &mut issues,
                "runtime.readiness.timeout",
                &r.readiness.timeout,
            );
            for (i, port) in r.ports.iter().enumerate() {
                one_of(
                    &mut issues,
                    &format!("runtime.ports[{i}].protocol"),
                    &port.protocol,
                    &["tcp", "udp"],
                );
            }
        }

        if let Some(s) = &self.sealed {
            if !valid_release(&s.release) {
                issues.push(ValidationIssue::new(
                    "sealed.release",
                    "must be `event_end`, `manual`, or `stage:<id>`",
                ));
            }
            // The serving policy, enforced here so an author sees it before packing
            // and again in the container (R5). A member cannot be sealed and
            // player-visible at once: it is either withheld until release or served,
            // never both.
            if let Some(g) = &self.generate {
                for member in &s.members {
                    if g.outputs
                        .iter()
                        .any(|o| &o.name == member && o.player_visible)
                    {
                        issues.push(ValidationIssue::new(
                            "sealed.members",
                            format!(
                                "`{member}` is both sealed and player-visible \
                                 (spec §5.3, R5)"
                            ),
                        ));
                    }
                }
            }
        }

        if let Some(v) = &self.verify {
            non_empty(&mut issues, "verify.solver", &v.solver);
            non_empty(&mut issues, "verify.expect", &v.expect);
            if let Some(live) = &v.live {
                non_empty(&mut issues, "verify.live.interval", &live.interval);
            }
        }

        issues
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// Entries are emitted in whatever order the author wrote them; the canonical
/// encoder sorts and rejects duplicates, so this needs no ordering discipline.
fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

/// How a section's flag is derived.
///
/// `flag: derived` is the shorthand the design document leads with; the expanded
/// form names the derivation explicitly for a challenge that needs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagSpec {
    /// The one-word form: `flag: derived`.
    Shorthand(String),
    /// The expanded form.
    Detailed(FlagDetail),
}

impl FlagSpec {
    fn to_cbor(&self) -> Value {
        match self {
            Self::Shorthand(s) => Value::Text(s.clone()),
            Self::Detailed(d) => {
                let mut entries = vec![("derive", text(&d.derive))];
                if let Some(t) = &d.template {
                    entries.push(("template", Value::Text(t.clone())));
                }
                if let Some(s) = &d.scope {
                    entries.push(("scope", Value::Text(s.clone())));
                }
                map(entries)
            }
        }
    }
}

/// The expanded `flag:` mapping.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlagDetail {
    /// Derivation function, e.g. `hkdf-sha256`.
    pub derive: String,
    /// Flag template, e.g. `ctf{rop_%s}`.
    #[serde(default)]
    pub template: Option<String>,
    /// `player`, `team`, or `event`.
    #[serde(default)]
    pub scope: Option<String>,
}

/// A hand-written deserializer so `flag:` accepts a scalar or a map without the
/// anonymous "did not match any variant" error an untagged enum would produce.
/// A misspelling inside the map still names the key, which is the whole point.
impl<'de> Deserialize<'de> for FlagSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FlagVisitor;

        impl<'de> Visitor<'de> for FlagVisitor {
            type Value = FlagSpec;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("`derived`, another derivation name, or a `flag:` mapping")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(FlagSpec::Shorthand(v.to_owned()))
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                use serde::de::value::MapAccessDeserializer;
                let detail = FlagDetail::deserialize(MapAccessDeserializer::new(map))?;
                Ok(FlagSpec::Detailed(detail))
            }
        }

        deserializer.deserialize_any(FlagVisitor)
    }
}

/// `generate:` — how the deterministic generator is declared.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateSpec {
    /// Generator module, by name.
    pub wasm: String,
    /// `strict`, `flag_only`, or `none`.
    pub determinism: String,
    /// Named outputs the generator produces.
    pub outputs: Vec<OutputSpec>,
}

impl GenerateSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("wasm", text(&self.wasm)),
            ("determinism", text(&self.determinism)),
            (
                "outputs",
                Value::Array(self.outputs.iter().map(OutputSpec::to_cbor).collect()),
            ),
        ])
    }
}

/// One `generate.outputs` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputSpec {
    /// Output name; indexes the manifest's name table.
    pub name: String,
    /// Whether the output may be served to a player.
    pub player_visible: bool,
}

impl OutputSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("name", text(&self.name)),
            ("player_visible", Value::Bool(self.player_visible)),
        ])
    }
}

/// `runtime:` — the runtime contract the future orchestrator consumes (design §2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSpec {
    /// Digest-pinned image reference.
    pub image: String,
    /// Exposed ports.
    pub ports: Vec<PortSpec>,
    /// Resource limits.
    pub resources: ResourcesSpec,
    /// `shared` or `per_team`.
    pub instancing: String,
    /// Instance lifetime, e.g. `30m`.
    pub ttl: String,
    /// Readiness probe.
    pub readiness: ReadinessSpec,
}

impl RuntimeSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("image", text(&self.image)),
            (
                "ports",
                Value::Array(self.ports.iter().map(PortSpec::to_cbor).collect()),
            ),
            ("resources", self.resources.to_cbor()),
            ("instancing", text(&self.instancing)),
            ("ttl", text(&self.ttl)),
            ("readiness", self.readiness.to_cbor()),
        ])
    }
}

/// One `runtime.ports` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortSpec {
    /// Container port.
    pub container: u64,
    /// `tcp` or `udp`.
    pub protocol: String,
}

impl PortSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("container", Value::Uint(self.container)),
            ("protocol", text(&self.protocol)),
        ])
    }
}

/// `runtime.resources`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcesSpec {
    /// CPU quota, e.g. `"0.5"`.
    pub cpu: String,
    /// Memory limit, e.g. `"256Mi"`.
    pub memory: String,
    /// PID limit.
    pub pids: u64,
}

impl ResourcesSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("cpu", text(&self.cpu)),
            ("memory", text(&self.memory)),
            ("pids", Value::Uint(self.pids)),
        ])
    }
}

/// `runtime.readiness`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessSpec {
    /// TCP port that must accept a connection.
    pub tcp: u64,
    /// Probe timeout, e.g. `30s`.
    pub timeout: String,
}

impl ReadinessSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("tcp", Value::Uint(self.tcp)),
            ("timeout", text(&self.timeout)),
        ])
    }
}

/// `sealed:` — which members are sealed and when they are released.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedSpec {
    /// `event_end`, `manual`, or `stage:<id>`.
    pub release: String,
    /// Sealed member names.
    pub members: Vec<String>,
}

impl SealedSpec {
    fn to_cbor(&self) -> Value {
        map(vec![
            ("release", text(&self.release)),
            (
                "members",
                Value::Array(
                    self.members
                        .iter()
                        .map(|m| Value::Text(m.clone()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// `verify:` — the solvability gate's declaration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifySpec {
    /// Solver module, by name.
    pub solver: String,
    /// What the solver must output, e.g. `flag`.
    pub expect: String,
    /// Whether the offline gate runs.
    pub offline: bool,
    /// The live gate's contract (design §3, pillar 5).
    #[serde(default)]
    pub live: Option<LiveSpec>,
}

impl VerifySpec {
    fn to_cbor(&self) -> Value {
        let mut entries = vec![
            ("solver", text(&self.solver)),
            ("expect", text(&self.expect)),
            ("offline", Value::Bool(self.offline)),
        ];
        if let Some(l) = &self.live {
            entries.push(("live", l.to_cbor()));
        }
        map(entries)
    }
}

/// `verify.live` — consumed by the orchestrator project, not this one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveSpec {
    /// Re-solve cadence, e.g. `5m`.
    pub interval: String,
}

impl LiveSpec {
    fn to_cbor(&self) -> Value {
        map(vec![("interval", text(&self.interval))])
    }
}
