#!/usr/bin/env python3

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STAGE388 = ROOT / "development" / "stage388"
STAGE387 = ROOT / "development" / "stage387"

EXPECTED_SOURCE_COMMIT = (
    "739cea647de6d64313be7be874a7aaa0295bc05e"
)

EXPECTED_STAGE387_DECISION = (
    "pqc_multi_implementation_interoperability_verified"
)

SUCCESS_DECISION = (
    "independent_assessment_evidence_package_ready"
)

REQUIRED_FALSE_FLAGS = (
    "external_assessment_completed",
    "formal_certification",
    "system_wide_formal_acceptance",
    "entire_system_quantum_safe",
)

FORBIDDEN_PATH_COMPONENTS = {
    "core",
    "private_core",
    "private",
    "secrets",
    "keys",
    "imported",
}

PRIVATE_PEM_PATTERNS = (
    re.compile(
        rb"-----BEGIN PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        rb"-----BEGIN ENCRYPTED PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END ENCRYPTED PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        rb"-----BEGIN RSA PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END RSA PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        rb"-----BEGIN EC PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END EC PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        rb"-----BEGIN DSA PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END DSA PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        rb"-----BEGIN OPENSSH PRIVATE KEY-----\s*"
        rb"([A-Za-z0-9+/=\r\n]+?)"
        rb"\s*-----END OPENSSH PRIVATE KEY-----",
        re.DOTALL,
    ),
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(
        "r",
        encoding="utf-8",
    ) as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(
            f"{path} must contain a JSON object"
        )

    return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def verify_sha_sidecar(
    sidecar: Path,
) -> tuple[bool, str]:
    if not sidecar.is_file():
        return (
            False,
            f"missing SHA sidecar: {sidecar}",
        )

    line = sidecar.read_text(
        encoding="utf-8"
    ).strip()

    parts = line.split()

    if len(parts) < 2:
        return (
            False,
            f"invalid SHA sidecar: {sidecar}",
        )

    expected_hash = parts[0].strip()

    if not re.fullmatch(
        r"[0-9a-fA-F]{64}",
        expected_hash,
    ):
        return (
            False,
            f"invalid SHA-256 value: {sidecar}",
        )

    recorded_path = parts[-1].lstrip("*")

    target = ROOT / recorded_path

    if not target.is_file():
        return (
            False,
            f"SHA target missing: {recorded_path}",
        )

    actual_hash = sha256_file(target)

    if actual_hash.lower() != expected_hash.lower():
        return (
            False,
            f"SHA mismatch: {recorded_path}",
        )

    return (
        True,
        f"SHA verified: {recorded_path}",
    )


def publication_candidates() -> list[str]:
    result = subprocess.check_output(
        [
            "git",
            "-C",
            str(ROOT),
            "ls-files",
            "-co",
            "--exclude-standard",
            "-z",
        ]
    )

    names = []

    for raw in result.split(b"\0"):
        if not raw:
            continue

        names.append(
            raw.decode(
                "utf-8",
                errors="surrogateescape",
            )
        )

    return sorted(set(names))


def path_has_forbidden_component(
    relative_name: str,
) -> bool:
    parts = Path(relative_name).parts

    return any(
        component in FORBIDDEN_PATH_COMPONENTS
        for component in parts
    )


def contains_structural_private_pem(
    path: Path,
) -> bool:
    try:
        data = path.read_bytes()
    except OSError:
        return False

    for pattern in PRIVATE_PEM_PATTERNS:
        for match in pattern.finditer(data):
            body = re.sub(
                rb"\s+",
                b"",
                match.group(1),
            )

            try:
                decoded = base64.b64decode(
                    body,
                    validate=True,
                )
            except Exception:
                continue

            if len(decoded) >= 32:
                return True

    return False


def check_required_false_flags(
    scope: dict[str, Any],
    limitations: dict[str, Any],
    contract: dict[str, Any],
) -> list[str]:
    failures = []

    scope_state = scope.get(
        "required_final_state",
        {},
    )

    limitation_state = limitations.get(
        "known_limitations",
        {},
    )

    contract_state = contract.get(
        "required_false_flags",
        {},
    )

    for key in REQUIRED_FALSE_FLAGS:
        values = {
            "scope": scope_state.get(key),
            "limitations": limitation_state.get(key),
            "contract": contract_state.get(key),
        }

        for source_name, value in values.items():
            if value is not False:
                failures.append(
                    f"{key} must be false "
                    f"in {source_name}"
                )

    return failures


def main() -> int:
    failures: list[str] = []
    checks: dict[str, bool] = {}

    required_stage388_files = [
        STAGE388 / "stage388_assessment_scope.json",
        STAGE388 / "stage388_threat_model.json",
        STAGE388 / "stage388_trust_boundaries.json",
        STAGE388 / "stage388_guarantees.json",
        STAGE388 / "stage388_non_guarantees.json",
        STAGE388 / "stage388_known_limitations.json",
        STAGE388 / "stage388_test_matrix.json",
        STAGE388 / "stage388_provenance.json",
        STAGE388 / "stage388_evidence_package_contract.json",
        STAGE388 / "verify_stage388_assessment_package.py",
    ]

    missing = [
        str(path.relative_to(ROOT))
        for path in required_stage388_files
        if not path.is_file()
    ]

    checks["required_stage388_files_present"] = (
        not missing
    )

    if missing:
        for name in missing:
            failures.append(
                f"missing Stage388 file: {name}"
            )

    try:
        scope = load_json(
            STAGE388
            / "stage388_assessment_scope.json"
        )
        limitations = load_json(
            STAGE388
            / "stage388_known_limitations.json"
        )
        provenance = load_json(
            STAGE388
            / "stage388_provenance.json"
        )
        contract = load_json(
            STAGE388
            / "stage388_evidence_package_contract.json"
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "stage": 388,
                    "decision": "fail_closed",
                    "verification_status": "failed",
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1

    checks["stage_number_valid"] = (
        scope.get("stage") == 388
        and provenance.get("stage") == 388
        and contract.get("stage") == 388
    )

    if not checks["stage_number_valid"]:
        failures.append(
            "Stage388 stage number mismatch"
        )

    checks["source_stage_valid"] = (
        scope.get("source_stage") == 387
        and provenance.get("source_stage") == 387
        and contract.get("source_stage") == 387
    )

    if not checks["source_stage_valid"]:
        failures.append(
            "source_stage must remain 387"
        )

    checks["source_commit_bound"] = (
        provenance.get("source_commit")
        == EXPECTED_SOURCE_COMMIT
    )

    if not checks["source_commit_bound"]:
        failures.append(
            "Stage387 source commit mismatch"
        )

    checks["stage387_results_declared_immutable"] = (
        provenance.get(
            "stage387_results_modified_by_stage388"
        )
        is False
        and scope.get(
            "assessment_target",
            {},
        ).get(
            "stage387_results_preserved"
        )
        is True
    )

    if not checks[
        "stage387_results_declared_immutable"
    ]:
        failures.append(
            "Stage387 inherited result preservation "
            "declaration failed"
        )

    false_flag_failures = (
        check_required_false_flags(
            scope,
            limitations,
            contract,
        )
    )

    checks["required_false_flags_preserved"] = (
        not false_flag_failures
    )

    failures.extend(
        false_flag_failures
    )

    stage387_result_path = (
        STAGE387
        / "stage387_pqc_multi_implementation_"
        "interoperability_result.json"
    )

    try:
        stage387_result = load_json(
            stage387_result_path
        )
    except Exception as exc:
        failures.append(
            f"cannot load Stage387 result: {exc}"
        )
        stage387_result = {}

    stage387_checks = stage387_result.get(
        "checks",
        {},
    )

    stage387_limitations = stage387_result.get(
        "limitations",
        {},
    )

    checks["stage387_verified_result_valid"] = (
        stage387_result.get("stage") == 387
        and stage387_result.get("decision")
        == EXPECTED_STAGE387_DECISION
        and stage387_result.get(
            "verification_status"
        )
        == "verified"
        and stage387_checks.get(
            "openssl_mldsa65_verified"
        )
        is True
        and stage387_checks.get(
            "circl_mldsa65_verified"
        )
        is True
        and stage387_checks.get(
            "cross_implementation_result_match"
        )
        is True
        and stage387_checks.get(
            "private_key_published"
        )
        is False
        and stage387_limitations.get(
            "entire_system_quantum_safe"
        )
        is False
    )

    if not checks[
        "stage387_verified_result_valid"
    ]:
        failures.append(
            "Stage387 verified result state mismatch"
        )

    sha_sidecars = [
        STAGE387
        / "stage387_pqc_interoperability_policy.sha256",
        STAGE387
        / "stage387_pqc_multi_implementation_"
        "interoperability_result.sha256",
        STAGE387
        / "stage387_evidence_portability_manifest.sha256",
    ]

    sha_results = []

    for sidecar in sha_sidecars:
        ok, message = verify_sha_sidecar(
            sidecar
        )

        sha_results.append(ok)

        if not ok:
            failures.append(message)

    checks["stage387_sha_bindings_valid"] = (
        all(sha_results)
    )

    contract_public_files = set(
        contract.get(
            "stage388_public_files",
            [],
        )
    )

    actual_stage388_candidates = {
        name
        for name in publication_candidates()
        if name.startswith(
            "development/stage388/"
        )
    }

    unexpected_stage388_files = sorted(
        actual_stage388_candidates
        - contract_public_files
    )

    missing_contract_files = sorted(
        contract_public_files
        - actual_stage388_candidates
    )

    checks["stage388_allowlist_exact"] = (
        not unexpected_stage388_files
        and not missing_contract_files
    )

    for name in unexpected_stage388_files:
        failures.append(
            f"unexpected Stage388 public file: {name}"
        )

    for name in missing_contract_files:
        failures.append(
            f"contract file not publication-visible: {name}"
        )

    candidates = publication_candidates()

    forbidden_candidate_paths = [
        name
        for name in candidates
        if path_has_forbidden_component(name)
    ]

    checks["forbidden_public_paths_absent"] = (
        not forbidden_candidate_paths
    )

    for name in forbidden_candidate_paths:
        failures.append(
            f"forbidden publication path: {name}"
        )

    structural_private_pem_files = []

    for name in candidates:
        candidate_path = ROOT / name

        if not candidate_path.is_file():
            continue

        if contains_structural_private_pem(
            candidate_path
        ):
            structural_private_pem_files.append(
                name
            )

    checks["structural_private_pem_absent"] = (
        not structural_private_pem_files
    )

    for name in structural_private_pem_files:
        failures.append(
            f"structural private PEM detected: {name}"
        )

    checks["success_decision_contract_valid"] = (
        contract.get("success_decision")
        == SUCCESS_DECISION
    )

    if not checks[
        "success_decision_contract_valid"
    ]:
        failures.append(
            "success decision contract mismatch"
        )

    critical_failure_count = len(failures)

    if critical_failure_count == 0:
        decision = SUCCESS_DECISION
        verification_status = "verified"
    else:
        decision = "fail_closed"
        verification_status = "failed"

    output = {
        "schema_version": "1.0",
        "stage": 388,
        "engine": (
            "independent_assessment_readiness_"
            "evidence_package_gate"
        ),
        "source_stage": 387,
        "source_commit": EXPECTED_SOURCE_COMMIT,
        "decision": decision,
        "verification_status": verification_status,
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
    }

    print(
        json.dumps(
            output,
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
    sys.exit(main())
