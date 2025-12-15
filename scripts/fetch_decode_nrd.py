#!/usr/bin/env python3
import argparse
import base64
import os
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

TARGET_NAME = "nrd-phishing-30day"


def download(url: str, dst_path: str) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "github-actions-nrd-fetch/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(dst_path, "wb") as f:
            f.write(r.read())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code}: {e.reason}") from None
    except urllib.error.URLError as e:
        raise SystemExit(f"URL Error: {e.reason}") from None


def decode_base64_line_to_text(line: bytes) -> str | None:
    s = line.strip()
    if not s:
        return None
    try:
        b64 = s.decode("ascii")
    except UnicodeDecodeError:
        return None

    pad = (-len(b64)) % 4
    if pad:
        b64 += "=" * pad

    try:
        decoded = base64.b64decode(b64, validate=False)
        text = decoded.decode("utf-8", errors="strict").strip()
        return text if text else None
    except Exception:
        return None


def extract_member_by_basename(tgz_path: str, basename: str, dst_path: str) -> bool:
    with tarfile.open(tgz_path, "r:gz") as tf:
        member = None
        for m in tf.getmembers():
            if m.isfile() and os.path.basename(m.name) == basename:
                member = m
                break

        if member is None:
            return False

        src = tf.extractfile(member)
        if src is None:
            return False

        with src, open(dst_path, "wb") as out:
            out.write(src.read())

    return True


def decode_file(src_path: str, dst_path: str) -> tuple[int, int]:
    decoded = 0
    skipped = 0

    with open(src_path, "rb") as fin, open(dst_path, "w", encoding="utf-8", newline="\n") as fout:
        for raw in fin:
            text = decode_base64_line_to_text(raw)
            if text is None:
                skipped += 1
                continue
            fout.write(text + "\n")
            decoded += 1

    return decoded, skipped


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="Tar.gz URL")
    ap.add_argument("--outdir", default=".", help="Where to write decoded-* file")
    args = ap.parse_args()

    outdir = os.path.abspath(args.outdir)
    os.makedirs(outdir, exist_ok=True)

    decoded_name = f"decoded-{TARGET_NAME}"
    decoded_path = os.path.join(outdir, decoded_name)

    with tempfile.TemporaryDirectory() as td:
        tgz_path = os.path.join(td, "feed.tar.gz")
        extracted_path = os.path.join(td, TARGET_NAME)

        print(f"Downloading feed")
        download(args.url, tgz_path)

        ok = extract_member_by_basename(tgz_path, TARGET_NAME, extracted_path)
        if not ok:
            print(f"ERROR: '{TARGET_NAME}' not found in archive", file=sys.stderr)
            return 2

        decoded, skipped = decode_file(extracted_path, decoded_path)

        print(f"Wrote {decoded_path}")
        print(f"Decoded lines {decoded}")
        print(f"Skipped lines {skipped}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

