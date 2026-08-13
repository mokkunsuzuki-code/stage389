#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]

VERIFIER_RELATIVE = Path(
    "development/stage388/"
    "verify_stage388_assessment_package.py"
)


def run_verifier(
    repo: Path,
) -> tuple[int, dict]:
    result = subprocess.run(
        [
            "python3",
            str(repo / VERIFIER_RELATIVE),
        ],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    try:
        payload = json.loads(
            result.stdout
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Verifier did not return valid JSON.\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        ) from exc

    return (
        result.returncode,
        payload,
    )


def copy_repository() -> Path:
    temp_root = Path(
        tempfile.mkdtemp(
            prefix="stage388-test-"
        )
    )

    destination = (
        temp_root
        / "repository"
    )

    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(
            ".git",
            "__pycache__",
            "*.pyc",
        ),
    )

    subprocess.run(
        [
            "git",
            "init",
            "-q",
        ],
        cwd=destination,
        check=True,
    )

    subprocess.run(
        [
            "git",
            "add",
            ".",
            "-f",
        ],
        cwd=destination,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    return destination


def load_json(
    path: Path,
) -> dict:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_json(
    path: Path,
    data: dict,
) -> None:
    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def expect_fail_closed(
    name: str,
    mutate: Callable[[Path], None],
) -> None:
    repo = copy_repository()

    try:
        mutate(repo)

        exit_code, payload = (
            run_verifier(repo)
        )

        decision = payload.get(
            "decision"
        )

        status = payload.get(
            "verification_status"
        )

        if (
            exit_code == 0
            or decision != "fail_closed"
            or status != "failed"
        ):
            raise AssertionError(
                f"{name}: expected fail_closed, "
                f"got exit={exit_code}, "
                f"decision={decision}, "
                f"status={status}"
            )

        print(
            f"PASS: {name}"
        )

    finally:
        shutil.rmtree(
            repo.parent,
            ignore_errors=True,
        )


def mutate_stage387_result(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage387/"
        "stage387_pqc_multi_implementation_"
        "interoperability_result.json"
    )

    data = load_json(path)

    data["decision"] = (
        "tampered_stage387_result"
    )

    write_json(
        path,
        data,
    )


def remove_required_stage388_file(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_threat_model.json"
    )

    path.unlink()


def mutate_stage387_sha_target(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage387/"
        "stage387_pqc_interoperability_policy.json"
    )

    with path.open(
        "a",
        encoding="utf-8",
    ) as handle:
        handle.write(
            "\n"
        )


def add_private_material(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "test_private_material.txt"
    )

    path.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n"
        "-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    subprocess.run(
        [
            "git",
            "add",
            "-f",
            str(
                path.relative_to(repo)
            ),
        ],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def promote_external_assessment(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_known_limitations.json"
    )

    data = load_json(path)

    data[
        "known_limitations"
    ][
        "external_assessment_completed"
    ] = True

    write_json(
        path,
        data,
    )


def promote_formal_certification(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_assessment_scope.json"
    )

    data = load_json(path)

    data[
        "required_final_state"
    ][
        "formal_certification"
    ] = True

    write_json(
        path,
        data,
    )


def promote_system_acceptance(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_evidence_package_contract.json"
    )

    data = load_json(path)

    data[
        "required_false_flags"
    ][
        "system_wide_formal_acceptance"
    ] = True

    write_json(
        path,
        data,
    )


def promote_quantum_safe(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_known_limitations.json"
    )

    data = load_json(path)

    data[
        "known_limitations"
    ][
        "entire_system_quantum_safe"
    ] = True

    write_json(
        path,
        data,
    )


def mutate_source_commit(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_provenance.json"
    )

    data = load_json(path)

    data[
        "source_commit"
    ] = (
        "000000000000000000000000000000"
        "0000000000"
    )

    write_json(
        path,
        data,
    )


def change_success_decision(
    repo: Path,
) -> None:
    path = (
        repo
        / "development/stage388/"
        "stage388_evidence_package_contract.json"
    )

    data = load_json(path)

    data[
        "success_decision"
    ] = (
        "external_assessment_completed"
    )

    write_json(
        path,
        data,
    )


def baseline_test() -> None:
    exit_code, payload = (
        run_verifier(ROOT)
    )

    expected_decision = (
        "independent_assessment_"
        "evidence_package_ready"
    )

    if exit_code != 0:
        raise AssertionError(
            "baseline verifier failed"
        )

    if payload.get(
        "decision"
    ) != expected_decision:
        raise AssertionError(
            "baseline decision mismatch"
        )

    if payload.get(
        "critical_failure_count"
    ) != 0:
        raise AssertionError(
            "baseline has critical failures"
        )

    limitations = payload.get(
        "limitations",
        {},
    )

    required_false = (
        "external_assessment_completed",
        "formal_certification",
        "system_wide_formal_acceptance",
        "entire_system_quantum_safe",
    )

    for key in required_false:
        if limitations.get(key) is not False:
            raise AssertionError(
                f"baseline limitation "
                f"{key} must be false"
            )

    print(
        "PASS: baseline success state"
    )


def main() -> int:
    baseline_test()

    tests = [
        (
            "F01 Stage387 result tampering",
            mutate_stage387_result,
        ),
        (
            "F02 required evidence missing",
            remove_required_stage388_file,
        ),
        (
            "F03 Stage387 SHA mismatch",
            mutate_stage387_sha_target,
        ),
        (
            "F04 private material publication",
            add_private_material,
        ),
        (
            "F05 external assessment false->true",
            promote_external_assessment,
        ),
        (
            "F06 formal certification false->true",
            promote_formal_certification,
        ),
        (
            "F07 system-wide acceptance false->true",
            promote_system_acceptance,
        ),
        (
            "F08 entire-system quantum-safe false->true",
            promote_quantum_safe,
        ),
        (
            "F09 Stage387 source commit mismatch",
            mutate_source_commit,
        ),
        (
            "F10 success-decision unauthorized promotion",
            change_success_decision,
        ),
    ]

    for name, mutation in tests:
        expect_fail_closed(
            name,
            mutation,
        )

    print()
    print(
        "PASS: all Stage388 Fail-Closed tests passed"
    )

    print(
        f"total_negative_tests={len(tests)}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
