#!/usr/bin/env bash
# Build the two guest modules, pack the bundle, run the offline gate, then deploy
# the bundle into a scratch directory and play it as a subject would receive it.
#
# Everything is development-local: the event secret below is a placeholder, and
# nothing here signs the bundle (that is `ctf sign` with an authoring key).
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)
WORKSPACE="$HERE/../.."

# The CLI's query macros read the committed `.sqlx` cache, so no database is needed.
export SQLX_OFFLINE="${SQLX_OFFLINE:-true}"

# A development secret, not an event secret. Override it to get a different
# subject seed, and therefore a different flag, layer names and archive.
SECRET="${CTF_EVENT_SECRET:-0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20}"
CTF=(cargo run --quiet --manifest-path "$WORKSPACE/Cargo.toml" -p ctf-cli --)
# Reuse the workspace target directory so `play` does not rebuild wasmtime.
PLAY_TARGET="${CARGO_TARGET_DIR:-$WORKSPACE/target}"

rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

echo "== building guests"
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path generator/Cargo.toml
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path solver/Cargo.toml
cp generator/target/wasm32-unknown-unknown/release/zipception_generator.wasm gen.wasm
cp solver/target/wasm32-unknown-unknown/release/zipception_solver.wasm solver.wasm
ls -l gen.wasm solver.wasm

echo "== validating"
"${CTF[@]}" validate challenge.yaml

echo "== packing (the bundle carries gen.wasm)"
"${CTF[@]}" pack challenge.yaml --out zipception.ctf
# `grep -q` would close the pipe and kill `ctf inspect` with SIGPIPE, so capture
# the report first and match it afterwards.
inspection=$("${CTF[@]}" inspect zipception.ctf)
case "$inspection" in
  *" generator "*) ;;
  *)
    echo "zipception.ctf does not carry the generator section" >&2
    exit 1
    ;;
esac

echo "== offline gate (generator twice + cross-engine, then the solver)"
"${CTF[@]}" run challenge.yaml --secret "$SECRET" --status zipception.status.json

echo "== deploying: a directory with the bundle and nothing else"
# The solver is sealed until event end and never travels inside the bundle, so the
# scratch directory gets it only to let the ingest gate run. A player gets the
# bundle and their generated artifact, nothing else.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp zipception.ctf challenge.yaml solver.wasm "$work/"
(
  cd "$work"
  CARGO_TARGET_DIR="$PLAY_TARGET" cargo run --quiet \
    --manifest-path "$HERE/play/Cargo.toml" -- \
    zipception.ctf --secret "$SECRET" --subject reference --out played.zip \
    | tee play.log
  # The bundle's own generator section feeds this gate; `gen.wasm` is not here.
  "${CTF[@]}" verify zipception.ctf --challenge challenge.yaml \
    --secret "$SECRET" --out bundle.status.json >/dev/null
)
expected=$(sed -n 's/^flag: //p' "$work/play.log")
actual=$(python3 solve.py "$work/played.zip")
test "$expected" = "$actual"
echo "player solver recovered: $actual"
