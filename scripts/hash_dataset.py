"""Create a deterministic SHA-256 inventory for local dataset files."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expand_inputs(patterns: list[str]) -> list[Path]:
    matches: set[Path] = set()
    for pattern in patterns:
        expanded = glob.glob(pattern, recursive=True)
        if not expanded:
            raise FileNotFoundError(f"No files matched: {pattern}")
        matches.update(Path(item).resolve() for item in expanded if Path(item).is_file())

    if not matches:
        raise FileNotFoundError("No files were selected")

    return sorted(matches, key=lambda path: path.as_posix().lower())


def display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def build_inventory(paths: list[Path], root: Path) -> dict[str, object]:
    return {
        "algorithm": "SHA-256",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "path": display_path(path, root),
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in paths
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Record file sizes and SHA-256 digests in a JSON inventory."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="File paths or glob patterns. Quote recursive globs on Windows.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write JSON to this path instead of standard output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = Path.cwd().resolve()
    try:
        paths = expand_inputs(args.inputs)
    except FileNotFoundError as error:
        raise SystemExit(f"error: {error}") from None
    inventory = build_inventory(paths, root)
    rendered = json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"

    if args.output is None:
        print(rendered, end="")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
