#!/usr/bin/env bash
# Build the two guest modules, pack the bundle, run the offline gate, and show one
# generated archive solved by the reference player solver.
#
# Everything is development-local: the event secret below is a placeholder, and
# nothing here signs the bundle (that is `ctf sign` with an authoring key).
set -euo pipefail
cd "$(dirname "$0")"

# The CLI's query macros read the committed `.sqlx` cache, so no database is needed.
export SQLX_OFFLINE="${SQLX_OFFLINE:-true}"

# A development secret, not an event secret. Override it to get a different
# subject seed, and therefore a different flag and different layer names.
SECRET="${CTF_EVENT_SECRET:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20}"
CTF=(cargo run --quiet --manifest-path ../../Cargo.toml -p ctf-cli --)

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

echo "== building guests"
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path generator/Cargo.toml
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path solver/Cargo.toml
cp generator/target/wasm32-unknown-unknown/release/zipception_generator.wasm gen.wasm
cp solver/target/wasm32-unknown-unknown/release/zipception_solver.wasm solver.wasm
ls -l gen.wasm solver.wasm

echo "== validating"
"${CTF[@]}" validate challenge.yaml

echo "== packing"
"${CTF[@]}" pack challenge.yaml --out zipception.ctf

echo "== offline gate (generator twice + cross-engine, then the solver)"
"${CTF[@]}" run challenge.yaml --secret "$SECRET" --status zipception.status.json

echo "== rendering one archive and solving it with the player solver"
# A fixed illustrative seed. A real deployment uses the per-subject seed of 22.2,
# which is what the gate above does.
cargo run --quiet --manifest-path generator/Cargo.toml --bin preview -- \
  2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
  inception.zip
expected=$(cargo run --quiet --manifest-path generator/Cargo.toml --bin preview -- \
  2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a \
  inception.zip | sed -n 's/^flag: //p')
actual=$(python3 solve.py inception.zip)
test "$expected" = "$actual"
echo "player solver recovered: $actual"
