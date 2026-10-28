#!/usr/bin/env python3
"""Streaming solver for Zipception, ported with the challenge.

Every layer is unwrapped in memory, so no intermediate path is ever created on
disk and the operating system path limit (PATH_MAX / MAX_PATH) does not apply.
Standard library only; runs on Windows, Linux and macOS.

Usage:
    python3 solve.py inception.zip           # prints the flag
    python3 solve.py inception.zip -q        # no progress lines
    python3 solve.py inception.zip --limit 500

The flag is the 16-character value spec 22.3 derives for the subject, so it has
no wrapper; `--show-depth` reports how many layers were unwrapped.
"""
from __future__ import annotations

import argparse
import io
import sys
import time
import zipfile


def pick_entry(archive: zipfile.ZipFile) -> zipfile.ZipInfo:
    """Return the entry to descend into, preferring a *.zip entry."""
    files = [info for info in archive.infolist() if not info.is_dir()]
    if not files:
        raise ValueError("archive contains no file entries")
    for info in files:
        if info.filename.lower().endswith(".zip"):
            return info
    return files[0]


def solve(data: bytes, limit: int = 0) -> tuple[int, str, bytes]:
    """Unwrap `data` until it is no longer a ZIP archive."""
    depth = 0
    entry_name = ""
    while True:
        if limit and depth >= limit:
            raise RuntimeError(f"exceeded --limit of {limit} layers")
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError):
            if depth == 0:
                raise
            return depth, entry_name, data
        entry = pick_entry(archive)
        entry_name = entry.filename
        data = archive.read(entry)
        depth += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unwrap Zipception archives in memory.")
    parser.add_argument("archive", help="nested archive, or - for stdin")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    parser.add_argument("--limit", type=int, default=0, help="maximum layers (0 = unlimited)")
    parser.add_argument("--show-depth", action="store_true", help="print the layer count")
    args = parser.parse_args(argv)

    if args.archive == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.archive, "rb") as handle:
            data = handle.read()

    if not args.quiet:
        print(f"[*] input: {len(data)} bytes", file=sys.stderr)

    started = time.monotonic()
    depth, entry, core = solve(data, limit=args.limit)
    elapsed = time.monotonic() - started

    if not args.quiet:
        print(
            f"[*] unwrapped {depth} layers in {elapsed:.3f}s; "
            f"core entry: {entry} ({len(core)} bytes)",
            file=sys.stderr,
        )

    sys.stdout.buffer.write(core)
    if not core.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    if args.show_depth:
        print(depth, file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as error:
        print(f"[!] {error}", file=sys.stderr)
        raise SystemExit(2)
