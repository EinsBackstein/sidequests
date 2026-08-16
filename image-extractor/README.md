# Image Extractor

Small command-line helper that extracts video frames to lossless PNG files with FFmpeg.

## Usage

```sh
python3 extract_frames.py VIDEO [OUTPUT_DIR]
```

If `OUTPUT_DIR` is omitted, frames are written to `<video-stem>_frames/`; both that default and the example `frames/` output directory are ignored by Git.

The script uses the FFmpeg binary supplied by the `imageio_ffmpeg` Python package. Generated frames are ignored by Git.

## Structure

```text
image-extractor/
├── extract_frames.py   # CLI and extraction logic
├── README.md           # usage and project notes
├── .gitignore          # ignores generated frames
└── frames/             # generated PNG output
```
