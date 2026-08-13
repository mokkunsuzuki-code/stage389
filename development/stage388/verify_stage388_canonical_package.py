#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

STAGE388 = (
    ROOT
    / "development/stage388"
)

BASE_VERIFIER = (
    STAGE388
    / "verify_stage388_assessment_package.py"
)

MANIFEST = (
    STAGE388
    / "stage388_evidence_manifest.json"
)

MANIFEST_SHA = (
    STAGE388
    / "stage388_evidence_manifest.sha256"
)

SUCCESS_DECISION = (
    "independent_assessment_evidence_package_ready"
)

EXPECTED_SOURCE_COMMIT = (
    "739cea647de6d64313be7be874a7aaa0295bc05e"
)


def sha256_bytes(
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(
                chunk
            )

    return digest.hexdigest()


def canonical_bytes(
    data: object,
) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )


def load_json(
    path: Path,
) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            f"{path} must contain "
            "a JSON object"
        )

    return data


def run_base_verifier() -> tuple[
    int,
    dict[str, Any],
]:
    result = subprocess.run(
        [
            sys.executable,
            str(BASE_VERIFIER),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    try:
        payload = json.loads(
            result.stdout
        )
    except json.JSONDecodeError:
        return (
            1,
            {
                "decision": "fail_closed",
                "verification_status": "failed",
                "error": (
                    "base verifier returned "
                    "invalid JSON"
                ),
            },
        )

    return (
        result.returncode,
        payload,
    )


def main() -> int:
    failures: list[str] = []

    checks = {
        "base_stage388_verifier_valid": False,
        "manifest_present": False,
        "manifest_sha_sidecar_valid": False,
        "manifest_metadata_valid": False,
        "manifest_entry_count_valid": False,
        "manifest_entries_valid": False,
        "canonical_package_hash_valid": False,
        "stage389_timestamp_not_claimed": False,
    }

    base_exit, base = (
        run_base_verifier()
    )

    checks[
        "base_stage388_verifier_valid"
    ] = (
        base_exit == 0
        and base.get(
            "decision"
        )
        == SUCCESS_DECISION
        and base.get(
            "critical_failure_count"
        )
        == 0
    )

    if not checks[
        "base_stage388_verifier_valid"
    ]:
        failures.append(
            "base Stage388 verifier failed"
        )

    if not MANIFEST.is_file():
        failures.append(
            "canonical evidence manifest missing"
        )
    else:
        checks[
            "manifest_present"
        ] = True

    if (
        MANIFEST.is_file()
        and MANIFEST_SHA.is_file()
    ):
        line = MANIFEST_SHA.read_text(
            encoding="utf-8"
        ).strip()

        parts = line.split()

        expected_hash = (
            parts[0]
            if len(parts) >= 2
            else ""
        )

        recorded_path = (
            parts[-1].lstrip("*")
            if len(parts) >= 2
            else ""
        )

        checks[
            "manifest_sha_sidecar_valid"
        ] = (
            expected_hash
            == sha256_file(
                MANIFEST
            )
            and recorded_path
            == (
                "development/stage388/"
                "stage388_evidence_manifest.json"
            )
        )

    if not checks[
        "manifest_sha_sidecar_valid"
    ]:
        failures.append(
            "manifest SHA-256 sidecar mismatch"
        )

    try:
        manifest = load_json(
            MANIFEST
        )
    except Exception as exc:
        failures.append(
            f"manifest load failed: {exc}"
        )
        manifest = {}

    checks[
        "manifest_metadata_valid"
    ] = (
        manifest.get(
            "stage"
        )
        == 388
        and manifest.get(
            "source_stage"
        )
        == 387
        and manifest.get(
            "source_commit"
        )
        == EXPECTED_SOURCE_COMMIT
    )

    if not checks[
        "manifest_metadata_valid"
    ]:
        failures.append(
            "manifest metadata mismatch"
        )

    entries = manifest.get(
        "entries",
        [],
    )

    checks[
        "manifest_entry_count_valid"
    ] = (
        isinstance(
            entries,
            list,
        )
        and manifest.get(
            "entry_count"
        )
        == len(entries)
        and len(entries) > 0
    )

    if not checks[
        "manifest_entry_count_valid"
    ]:
        failures.append(
            "manifest entry count mismatch"
        )

    entry_failures = []

    if isinstance(
        entries,
        list,
    ):
        for entry in entries:
            if not isinstance(
                entry,
                dict,
            ):
                entry_failures.append(
                    "non-object entry"
                )
                continue

            name = entry.get(
                "path"
            )

            expected_sha = entry.get(
                "sha256"
            )

            expected_size = entry.get(
                "size_bytes"
            )

            if not isinstance(
                name,
                str,
            ):
                entry_failures.append(
                    "entry path invalid"
                )
                continue

            path = ROOT / name

            if not path.is_file():
                entry_failures.append(
                    f"missing: {name}"
                )
                continue

            if (
                sha256_file(
                    path
                )
                != expected_sha
            ):
                entry_failures.append(
                    f"hash mismatch: {name}"
                )

            if (
                path.stat().st_size
                != expected_size
            ):
                entry_failures.append(
                    f"size mismatch: {name}"
                )

    checks[
        "manifest_entries_valid"
    ] = (
        not entry_failures
    )

    failures.extend(
        entry_failures
    )

    canonical_scope = {
        "schema_version": manifest.get(
            "schema_version"
        ),
        "stage": manifest.get(
            "stage"
        ),
        "source_stage": manifest.get(
            "source_stage"
        ),
        "source_commit": manifest.get(
            "source_commit"
        ),
        "entries": entries,
    }

    recalculated_package_hash = (
        sha256_bytes(
            canonical_bytes(
                canonical_scope
            )
        )
    )

    checks[
        "canonical_package_hash_valid"
    ] = (
        recalculated_package_hash
        == manifest.get(
            "canonical_package_sha256"
        )
    )

    if not checks[
        "canonical_package_hash_valid"
    ]:
        failures.append(
            "canonical package hash mismatch"
        )

    checks[
        "stage389_timestamp_not_claimed"
    ] = (
        manifest.get(
            "external_timestamp_status"
        )
        == "not_performed_stage388"
        and manifest.get(
            "timestamp_stage"
        )
        == 389
    )

    if not checks[
        "stage389_timestamp_not_claimed"
    ]:
        failures.append(
            "Stage388 must not claim "
            "Stage389 timestamp completion"
        )

    critical_failure_count = len(
        failures
    )

    decision = (
        SUCCESS_DECISION
        if critical_failure_count == 0
        else "fail_closed"
    )

    verification_status = (
        "verified"
        if critical_failure_count == 0
        else "failed"
    )

    result = {
        "schema_version": "1.0",
        "stage": 388,
        "engine": (
            "canonical_independent_assessment_"
            "evidence_package_verifier"
        ),
        "source_stage": 387,
        "source_commit": (
            EXPECTED_SOURCE_COMMIT
        ),
        "decision": decision,
        "verification_status": (
            verification_status
        ),
        "canonical_package_sha256": (
            manifest.get(
                "canonical_package_sha256"
            )
        ),
        "checks": checks,
        "critical_failure_count": (
            critical_failure_count
        ),
        "failures": failures,
        "limitations": {
            "external_assessment_completed": False,
            "formal_certification": False,
            "system_wide_formal_acceptance": False,
            "entire_system_quantum_safe": False,
        },
        "external_timestamp": {
            "rfc3161_verified": False,
            "opentimestamps_verified": False,
            "dual_timestamp_verified": False,
            "scheduled_stage": 389,
        },
    }

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    return (
        0
        if critical_failure_count == 0
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
