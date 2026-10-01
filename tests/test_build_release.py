"""Tests for the deterministic AI-11 release builder."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_release import (  # noqa: E402
    build_manifest,
    manifest_bytes,
    preserve_recorded_model_sizes,
    read_release_paths,
    write_deterministic_bundle,
)
from train_baselines import file_sha256  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class ReleasePathTests(unittest.TestCase):
    def test_rejects_unsorted_or_escaping_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("a", encoding="utf-8")
            (root / "b.txt").write_text("b", encoding="utf-8")
            listing = root / "files.txt"
            listing.write_text("b.txt\na.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sorted"):
                read_release_paths(root, listing)
            listing.write_text("../outside.txt\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                read_release_paths(root, listing)

    def test_bundle_bytes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release").mkdir()
            (root / "a.txt").write_text("alpha\n", encoding="utf-8")
            manifest = root / "release" / "release-manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            first = root / "first.zip"
            second = root / "second.zip"

            write_deterministic_bundle(root, ("a.txt",), manifest, first, "0.2.0")
            write_deterministic_bundle(root, ("a.txt",), manifest, second, "0.2.0")

            self.assertEqual(file_sha256(first), file_sha256(second))


class CommittedReleaseTests(unittest.TestCase):
    def test_committed_manifest_matches_every_release_input(self) -> None:
        manifest_path = ROOT / "release" / "release-manifest.json"
        committed = json.loads(manifest_path.read_text(encoding="utf-8"))
        model_paths = [
            ROOT / record["path"]
            for record in committed["external_model_artifacts"]
        ]
        present = [path.is_file() for path in model_paths]
        self.assertTrue(
            all(present) or not any(present),
            "external model artifacts must be either complete or absent",
        )
        expected = build_manifest(
            ROOT,
            ROOT / "release" / "release-files.txt",
            require_models=all(present),
        )
        if not any(present):
            for expected_record, committed_record in zip(
                expected["external_model_artifacts"],
                committed["external_model_artifacts"],
                strict=True,
            ):
                self.assertEqual(expected_record["path"], committed_record["path"])
                self.assertEqual(expected_record["sha256"], committed_record["sha256"])
            preserve_recorded_model_sizes(expected, committed)
        actual = manifest_path.read_bytes()

        self.assertEqual(actual, manifest_bytes(expected))
        self.assertEqual(expected["release"]["version"], "0.2.0")
        self.assertEqual(expected["release"]["license"], "MIT")
        self.assertEqual(len(expected["external_model_artifacts"]), 6)


if __name__ == "__main__":
    unittest.main()
