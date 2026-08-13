#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

OUTPUT = (
    ROOT
    / "development/stage388/"
    "stage388_evidence_manifest.json"
)

SIDECAR = (
    ROOT
    / "development/stage388/"
    "stage388_evidence_manifest.sha256"
)

SOURCE_COMMIT = (
    "739cea647de6d64313be7be874a7aaa0295bc05e"
)

PAYLOAD_FILES = [
    # Stage387 inherited evidence
    "development/stage387/stage387_pqc_interoperability_policy.json",
    "development/stage387/stage387_pqc_interoperability_policy.sha256",
    "development/stage387/stage387_pqc_multi_implementation_interoperability_result.json",
    "development/stage387/stage387_pqc_multi_implementation_interoperability_result.sha256",
    "development/stage387/stage387_evidence_portability_manifest.json",
    "development/stage387/stage387_evidence_portability_manifest.sha256",

    # Stage388 assessment definition
    "development/stage388/stage388_assessment_scope.json",
    "development/stage388/stage388_threat_model.json",
    "development/stage388/stage388_trust_boundaries.json",
    "development/stage388/stage388_guarantees.json",
    "development/stage388/stage388_non_guarantees.json",
    "development/stage388/stage388_known_limitations.json",
    "development/stage388/stage388_test_matrix.json",

    # Stage388 provenance / contract / executable verification
    "development/stage388/stage388_provenance.json",
    "development/stage388/stage388_evidence_package_contract.json",
    "development/stage388/verify_stage388_assessment_package.py",
    "development/stage388/test_stage388_fail_closed.py",
    "development/stage388/generate_stage388_evidence_manifest.py",
    "development/stage388/verify_stage388_canonical_package.py",

    # Stage388 independent-assessment documentation / CI
    "development/stage388/README.md",
    "README.md",
    ".github/workflows/stage388-independent-assessment-readiness.yml",
    "docs/index.html",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def canonical_bytes(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def main() -> int:
    entries = []

    for relative_name in sorted(
        PAYLOAD_FILES
    ):
        path = ROOT / relative_name

        if not path.is_file():
            raise SystemExit(
                f"FAIL: required payload missing: "
                f"{relative_name}"
            )

        entries.append(
            {
                "path": relative_name,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    canonical_scope = {
        "schema_version": "1.0",
        "stage": 388,
        "source_stage": 387,
        "source_commit": SOURCE_COMMIT,
        "entries": entries,
    }

    package_hash = sha256_bytes(
        canonical_bytes(
            canonical_scope
        )
    )

    manifest = {
        **canonical_scope,
        "entry_count": len(entries),
        "canonicalization": (
            "UTF-8 JSON; sort_keys=true; "
            "separators=(',', ':'); "
            "manifest self-hash excluded"
        ),
        "canonical_package_sha256": package_hash,
        "external_timestamp_status": (
            "not_performed_stage388"
        ),
        "timestamp_stage": 389,
    }

    OUTPUT.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest_hash = sha256_file(
        OUTPUT
    )

    relative_output = (
        OUTPUT.relative_to(ROOT)
        .as_posix()
    )

    SIDECAR.write_text(
        f"{manifest_hash}  "
        f"{relative_output}\n",
        encoding="utf-8",
    )

    print(
        "stage = 388"
    )

    print(
        "entry_count =",
        len(entries),
    )

    print(
        "canonical_package_sha256 =",
        package_hash,
    )

    print(
        "manifest_sha256 =",
        manifest_hash,
    )

    print(
        "external_timestamp_status = "
        "not_performed_stage388"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
