#!/usr/bin/env python3
"""Extract every frame of a video as lossless PNGs.

Usage: python3 extract_frames.py VIDEO [OUTDIR]
"""
import subprocess
import sys
from pathlib import Path

import imageio_ffmpeg

FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()


def extract(video: Path, outdir: Path) -> int:
    if not video.is_file():
        raise SystemExit(f"no such file: {video}")
    outdir.mkdir(parents=True, exist_ok=True)

    cmd = [
        FFMPEG, "-nostdin", "-y",
        "-i", str(video),
        "-fps_mode", "passthrough",  # every frame, no dup/drop
        "-pix_fmt", "rgb24",         # no chroma subsampling on output
        "-compression_level", "1",   # fast PNG; still lossless
        str(outdir / "frame_%06d.png"),
    ]
    proc = subprocess.run(cmd, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-2000:])
        raise SystemExit(proc.returncode)

    return len(list(outdir.glob("frame_*.png")))


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    video = Path(sys.argv[1])
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(video.stem + "_frames")
    n = extract(video, outdir)
    size = sum(f.stat().st_size for f in outdir.glob("frame_*.png"))
    print(f"{n} frames -> {outdir} ({size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
