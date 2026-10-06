from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile
from typing import Mapping
from urllib import request as urllib_request


REPO_ROOT = Path(__file__).resolve().parents[1]
# v2: blinded eval circuit (version 4); the semantic artifacts are unchanged from v1.
ARTIFACT_TAG = "proving-artifacts-v2"
ARTIFACT_NAME = "chainattest-proving-artifacts-v2.tar.gz"
ARTIFACT_URL = (
    "https://github.com/atikulmunna/chainattest/releases/download/"
    f"{ARTIFACT_TAG}/{ARTIFACT_NAME}"
)
ARCHIVE_SHA256 = "16f11588722ddd5d3f129ff0cb1e2bb5d99c3df20e3557e524b735af2e10ba15"
EXPECTED_FILES = {
    "circuits/semantic_attestation_js/semantic_attestation.wasm": (
        "e1c3a14ae58d6a6a85a0572647064f90a93954271499949d08f04e2d2bba9f1b"
    ),
    "circuits/semantic_attestation_final.zkey": (
        "6c9956fc938799e3736f375431b217e786c120abf6649c64d9dd52e239de9341"
    ),
    "circuits/eval_threshold_js/eval_threshold.wasm": (
        "8b4e7fdf35b032eaf75ce6fbfbf9f3c689e398036f6d503afbb29d5aa3195ff8"
    ),
    "circuits/eval_threshold_final.zkey": (
        "1592b22b96910ad52a9cdde3b09764a5db26bb9613bebdade70a848ba22d3a65"
    ),
}


class ProvingArtifactError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sha256(path: Path, expected_digest: str) -> None:
    actual_digest = sha256_file(path)
    if actual_digest != expected_digest:
        raise ProvingArtifactError(
            f"SHA-256 mismatch for {path.name}: expected {expected_digest}, got {actual_digest}"
        )


def download_archive(destination: Path) -> None:
    request = urllib_request.Request(
        ARTIFACT_URL,
        headers={"User-Agent": "ChainAttest-proving-artifact-fetcher/1"},
    )
    try:
        with urllib_request.urlopen(request, timeout=60) as response:
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output)
    except OSError as exc:
        raise ProvingArtifactError(f"could not download {ARTIFACT_URL}: {exc}") from exc


def _validated_members(
    archive: tarfile.TarFile,
    expected_files: Mapping[str, str],
) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        member_path = PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise ProvingArtifactError(f"unsafe archive path: {member.name}")
        if not member.isfile():
            raise ProvingArtifactError(f"non-regular archive entry: {member.name}")

        normalized_name = member_path.as_posix()
        if normalized_name in members:
            raise ProvingArtifactError(f"duplicate archive entry: {normalized_name}")
        if normalized_name not in expected_files:
            raise ProvingArtifactError(f"unexpected archive entry: {normalized_name}")
        members[normalized_name] = member

    missing = sorted(set(expected_files) - set(members))
    if missing:
        raise ProvingArtifactError(f"archive is missing required entries: {', '.join(missing)}")
    return members


def restore_proving_artifacts(
    archive_path: Path,
    destination_root: Path = REPO_ROOT,
    expected_files: Mapping[str, str] = EXPECTED_FILES,
) -> list[Path]:
    destination_root = destination_root.resolve()
    with tempfile.TemporaryDirectory(prefix="chainattest-proving-") as temporary_directory:
        staging_root = Path(temporary_directory)
        try:
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = _validated_members(archive, expected_files)
                for relative_name, expected_digest in expected_files.items():
                    source = archive.extractfile(members[relative_name])
                    if source is None:
                        raise ProvingArtifactError(f"could not read archive entry: {relative_name}")

                    staged_path = staging_root / Path(relative_name)
                    staged_path.parent.mkdir(parents=True, exist_ok=True)
                    with source, staged_path.open("wb") as output:
                        shutil.copyfileobj(source, output)
                    verify_sha256(staged_path, expected_digest)
        except (tarfile.TarError, OSError) as exc:
            raise ProvingArtifactError(f"could not read {archive_path}: {exc}") from exc

        restored_paths: list[Path] = []
        for relative_name in expected_files:
            destination = destination_root / Path(relative_name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staging_root / Path(relative_name), destination)
            restored_paths.append(destination)
        return restored_paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Restore pinned, checksum-verified ChainAttest Groth16 proving artifacts."
    )
    parser.add_argument(
        "--archive",
        type=Path,
        help="Use a local archive instead of downloading the pinned GitHub release asset.",
    )
    parser.add_argument(
        "--destination-root",
        type=Path,
        default=REPO_ROOT,
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.archive:
            archive_path = args.archive.resolve()
            verify_sha256(archive_path, ARCHIVE_SHA256)
            restored_paths = restore_proving_artifacts(archive_path, args.destination_root)
        else:
            with tempfile.TemporaryDirectory(prefix="chainattest-download-") as temporary_directory:
                archive_path = Path(temporary_directory) / ARTIFACT_NAME
                download_archive(archive_path)
                verify_sha256(archive_path, ARCHIVE_SHA256)
                restored_paths = restore_proving_artifacts(archive_path, args.destination_root)
    except ProvingArtifactError as exc:
        print(f"error: {exc}")
        return 1

    for path in restored_paths:
        print(f"restored {path.relative_to(args.destination_root.resolve())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
