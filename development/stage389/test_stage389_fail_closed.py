#!/usr/bin/env python3

import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

STAGE388_MANIFEST = (
    ROOT
    / "development"
    / "stage388"
    / "stage388_evidence_manifest.json"
)

STAGE389_DIR = (
    ROOT
    / "development"
    / "stage389"
)

VERIFIER = (
    STAGE389_DIR
    / "verify_stage389_dual_timestamp.py"
)

CONTRACT = (
    STAGE389_DIR
    / "stage389_timestamp_target_contract.json"
)

POLICY = (
    STAGE389_DIR
    / "stage389_timestamp_policy.json"
)

RFC_EVIDENCE = (
    STAGE389_DIR
    / "stage389_rfc3161_evidence.json"
)

OTS_EVIDENCE = (
    STAGE389_DIR
    / "stage389_opentimestamps_evidence.json"
)

SUCCESS_DECISION = (
    "independent_assessment_package_"
    "dual_timestamp_verified"
)


def run_verifier(root):
    verifier = (
        root
        / "development"
        / "stage389"
        / "verify_stage389_dual_timestamp.py"
    )

    completed = subprocess.run(
        [
            "python3",
            str(verifier),
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )

    if not completed.stdout.strip():
        raise AssertionError(
            "verifier produced no JSON output"
        )

    result = json.loads(
        completed.stdout
    )

    return (
        completed.returncode,
        result,
    )


def build_fixture():
    tmp = Path(
        tempfile.mkdtemp(
            prefix="stage389-fail-closed-"
        )
    )

    (
        tmp
        / "development"
        / "stage388"
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        tmp
        / "development"
        / "stage389"
    ).mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        STAGE388_MANIFEST,
        tmp
        / "development"
        / "stage388"
        / STAGE388_MANIFEST.name,
    )

    for source in [
        VERIFIER,
        CONTRACT,
        POLICY,
        RFC_EVIDENCE,
        OTS_EVIDENCE,
    ]:
        shutil.copy2(
            source,
            tmp
            / "development"
            / "stage389"
            / source.name,
        )

    return tmp


def assert_no_success(
    label,
    root,
):
    exit_code, result = run_verifier(
        root
    )

    decision = result.get(
        "decision"
    )

    dual = result.get(
        "dual_timestamp_verified",
        False,
    )

    if (
        decision
        == SUCCESS_DECISION
        or dual is True
    ):
        raise AssertionError(
            f"{label}: false acceptance detected"
        )

    print(
        f"PASS: {label}"
    )

    return (
        exit_code,
        result,
    )


def mutate_json(
    file_path,
    mutator,
):
    data = json.loads(
        file_path.read_text(
            encoding="utf-8"
        )
    )

    mutator(
        data
    )

    file_path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_f01_forged_boolean_claims():
    root = build_fixture()

    try:
        rfc_path = (
            root
            / "development"
            / "stage389"
            / RFC_EVIDENCE.name
        )

        ots_path = (
            root
            / "development"
            / "stage389"
            / OTS_EVIDENCE.name
        )

        mutate_json(
            rfc_path,
            lambda d: d.update(
                {
                    "evidence_status":
                        "verified",

                    "response_present":
                        True,

                    "message_imprint_matches_subject":
                        True,

                    "tsa_signature_verified":
                        True,

                    "tsa_certificate_chain_verified":
                        True,

                    "timestamp_time_verified":
                        True,

                    "rfc3161_verified":
                        True,
                }
            ),
        )

        mutate_json(
            ots_path,
            lambda d: d.update(
                {
                    "evidence_status":
                        "verified",

                    "proof_present":
                        True,

                    "target_matches_subject":
                        True,

                    "bitcoin_attestation_present":
                        True,

                    "bitcoin_confirmation_verified":
                        True,

                    "opentimestamps_verified":
                        True,
                }
            ),
        )

        _, result = assert_no_success(
            "F01 forged Boolean evidence cannot succeed",
            root,
        )

        checks = result[
            "checks"
        ]

        assert (
            checks[
                "rfc3161_verified"
            ]
            is False
        )

        assert (
            checks[
                "opentimestamps_verified"
            ]
            is False
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f02_manifest_tampering():
    root = build_fixture()

    try:
        manifest = (
            root
            / "development"
            / "stage388"
            / STAGE388_MANIFEST.name
        )

        with manifest.open(
            "ab"
        ) as handle:
            handle.write(
                b"\n"
            )

        exit_code, result = assert_no_success(
            "F02 Stage388 manifest tampering rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f03_contract_subject_hash_tampering():
    root = build_fixture()

    try:
        contract_path = (
            root
            / "development"
            / "stage389"
            / CONTRACT.name
        )

        mutate_json(
            contract_path,
            lambda d: d[
                "timestamp_subject"
            ].update(
                {
                    "sha256":
                        "0" * 64
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F03 timestamp subject hash tampering rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f04_stage388_package_hash_tampering():
    root = build_fixture()

    try:
        contract_path = (
            root
            / "development"
            / "stage389"
            / CONTRACT.name
        )

        mutate_json(
            contract_path,
            lambda d: d[
                "bound_stage388_package"
            ].update(
                {
                    "canonical_package_sha256":
                        "f" * 64
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F04 canonical package hash tampering rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f05_entry_count_tampering():
    root = build_fixture()

    try:
        contract_path = (
            root
            / "development"
            / "stage389"
            / CONTRACT.name
        )

        mutate_json(
            contract_path,
            lambda d: d[
                "bound_stage388_package"
            ].update(
                {
                    "canonical_entry_count":
                        22
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F05 Stage388 entry-count tampering rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f06_rfc_subject_mismatch():
    root = build_fixture()

    try:
        evidence_path = (
            root
            / "development"
            / "stage389"
            / RFC_EVIDENCE.name
        )

        mutate_json(
            evidence_path,
            lambda d: d[
                "timestamp_subject"
            ].update(
                {
                    "sha256":
                        "1" * 64
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F06 RFC3161 subject mismatch rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f07_ots_subject_mismatch():
    root = build_fixture()

    try:
        evidence_path = (
            root
            / "development"
            / "stage389"
            / OTS_EVIDENCE.name
        )

        mutate_json(
            evidence_path,
            lambda d: d[
                "timestamp_subject"
            ].update(
                {
                    "sha256":
                        "2" * 64
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F07 OTS subject mismatch rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f08_source_stage_tampering():
    root = build_fixture()

    try:
        contract_path = (
            root
            / "development"
            / "stage389"
            / CONTRACT.name
        )

        mutate_json(
            contract_path,
            lambda d: d.update(
                {
                    "source_stage":
                        387
                }
            ),
        )

        exit_code, result = assert_no_success(
            "F08 source-stage tampering rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f09_missing_required_evidence():
    root = build_fixture()

    try:
        missing = (
            root
            / "development"
            / "stage389"
            / OTS_EVIDENCE.name
        )

        missing.unlink()

        exit_code, result = assert_no_success(
            "F09 missing required evidence rejected",
            root,
        )

        assert exit_code != 0

        assert (
            result[
                "decision"
            ]
            == "fail_closed"
        )

    finally:
        shutil.rmtree(
            root
        )


def test_f10_pending_ots_not_success():
    root = build_fixture()

    try:
        _, result = assert_no_success(
            "F10 absent/pending external proof cannot promote success",
            root,
        )

        assert (
            result[
                "dual_timestamp_verified"
            ]
            is False
        )

    finally:
        shutil.rmtree(
            root
        )


def main():
    tests = [
        test_f01_forged_boolean_claims,
        test_f02_manifest_tampering,
        test_f03_contract_subject_hash_tampering,
        test_f04_stage388_package_hash_tampering,
        test_f05_entry_count_tampering,
        test_f06_rfc_subject_mismatch,
        test_f07_ots_subject_mismatch,
        test_f08_source_stage_tampering,
        test_f09_missing_required_evidence,
        test_f10_pending_ots_not_success,
    ]

    for test in tests:
        test()

    print()
    print(
        "PASS: all Stage389 Fail-Closed regression tests passed"
    )

    print(
        "total_negative_tests =",
        len(
            tests
        ),
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
