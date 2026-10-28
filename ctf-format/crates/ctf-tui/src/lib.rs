//! Postgres-backed ingest and the admin terminal UI for `.ctf`.
//!
//! See `README.md` for the security posture: no HTTP server, no auth layer, SSH
//! only, and ingest as a foreground operation.

pub mod app;
pub mod db;
pub mod ingest;
pub mod model;
pub mod ui;
