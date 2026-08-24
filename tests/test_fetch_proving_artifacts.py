from __future__ import annotations

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts.fetch_proving_artifacts import (
    ProvingArtifactError,
    restore_proving_artifacts,
    verify_sha256,
)


class FetchProvingArtifactsTest(unittest.TestCase):
    def _write_archive(self, archive_path: Path, entries: dict[str, bytes]) -> None:
        with tarfile.open(archive_path, mode="w:gz") as archive:
            for name, contents in entries.items():
                member = tarfile.TarInfo(name=name)
                member.size = len(contents)
                archive.addfile(member, io.BytesIO(contents))

    def test_restores_only_validated_files(self) -> None:
        entries = {
            "circuits/example_js/example.wasm": b"wasm",
            "circuits/example_final.zkey": b"zkey",
        }
        expected_files = {
            name: hashlib.sha256(contents).hexdigest()
            for name, contents in entries.items()
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "artifacts.tar.gz"
            destination = root / "destination"
            self._write_archive(archive_path, entries)

            restored = restore_proving_artifacts(archive_path, destination, expected_files)

            self.assertEqual(len(restored), 2)
            for name, contents in entries.items():
                self.assertEqual((destination / name).read_bytes(), contents)

    def test_rejects_unexpected_archive_entry(self) -> None:
        expected_contents = b"wasm"
        expected_files = {
            "circuits/example.wasm": hashlib.sha256(expected_contents).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "artifacts.tar.gz"
            self._write_archive(
                archive_path,
                {
                    "circuits/example.wasm": expected_contents,
                    "circuits/unexpected.zkey": b"unexpected",
                },
            )

            with self.assertRaisesRegex(ProvingArtifactError, "unexpected archive entry"):
                restore_proving_artifacts(archive_path, root / "destination", expected_files)

    def test_rejects_file_digest_mismatch_before_writing(self) -> None:
        expected_files = {
            "circuits/example.wasm": hashlib.sha256(b"expected").hexdigest(),
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "artifacts.tar.gz"
            destination = root / "destination"
            self._write_archive(archive_path, {"circuits/example.wasm": b"tampered"})

            with self.assertRaisesRegex(ProvingArtifactError, "SHA-256 mismatch"):
                restore_proving_artifacts(archive_path, destination, expected_files)
            self.assertFalse((destination / "circuits/example.wasm").exists())

    def test_rejects_archive_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            archive_path = Path(temporary_directory) / "artifacts.tar.gz"
            archive_path.write_bytes(b"tampered archive")

            with self.assertRaisesRegex(ProvingArtifactError, "SHA-256 mismatch"):
                verify_sha256(archive_path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
