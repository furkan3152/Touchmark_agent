#!/usr/bin/env python3
"""Edit the raw how-to recording: speed up the marked waits and export MP4 plus a poster.

    python scripts/pilot/cut_howto.py media-build/ frontend/brand/
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FAST_SECONDS = 1.6  # each marked wait plays in this long


def duration(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return float(out.strip())


def main(build: Path, dest: Path) -> None:
    raw = build / "raw.webm"
    marks = sorted(m["fast"] for m in json.loads((build / "marks.json").read_text()))
    total = duration(raw)
    segments, cursor = [], 0.0
    for start, end in marks:
        if start > cursor:
            segments.append((cursor, start, 1.0))
        segments.append((start, end, max(1.0, (end - start) / FAST_SECONDS)))
        cursor = end
    segments.append((cursor, total, 1.0))
    # Each segment is encoded on its own and the pieces are joined without re-encoding: one
    # filter graph over every segment held all their frames in memory at once.
    dest.mkdir(parents=True, exist_ok=True)
    pieces = []
    for i, (a, b, speed) in enumerate(segments):
        piece = build / f"segment-{i:02d}.mp4"
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-ss", f"{a:.2f}", "-to", f"{b:.2f}", "-i", str(raw),
                        "-vf", f"setpts=(PTS-STARTPTS)/{speed:.3f},fps=30", "-an", "-c:v", "libx264", "-preset", "slow",
                        "-crf", "29", "-pix_fmt", "yuv420p", str(piece)], check=True)
        pieces.append(piece)
    listing = build / "segments.txt"
    listing.write_text("".join(f"file '{p.name}'\n" for p in pieces))
    video = dest / "touchmark-how-to.mp4"
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(listing),
                    "-c", "copy", "-movflags", "+faststart", str(video)], check=True)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-ss", "1.8", "-i", str(video), "-frames:v", "1",
                    str(dest / "video-poster.png")], check=True)
    print(f"{video}: {duration(video):.1f}s, {video.stat().st_size / 1e6:.1f} MB; segments {segments}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
