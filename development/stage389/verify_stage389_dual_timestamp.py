#!/usr/bin/env python3

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

STAGE388_MANIFEST = (
    ROOT
    / "development"
    / "stage388"
    / "stage388_evidence_manifest.json"
)

CONTRACT_PATH = (
    ROOT
    / "development"
    / "stage389"
    / "stage389_timestamp_target_contract.json"
)

POLICY_PATH = (
    ROOT
    / "development"
    / "stage389"
    / "stage389_timestamp_policy.json"
)

RFC3161_METADATA_PATH = (
    ROOT
    / "development"
    / "stage389"
    / "stage389_rfc3161_evidence.json"
)

OTS_METADATA_PATH = (
    ROOT
    / "development"
    / "stage389"
    / "stage389_opentimestamps_evidence.json"
)

# Raw external proof material is intentionally outside
# the publication-visible development/ and docs/ trees.
RFC3161_RESPONSE_PATH = (
    ROOT
    / "private"
    / "stage389-timestamps"
    / "rfc3161"
    / "response.tsr"
)

OTS_PRIVATE_DIR = (
    ROOT
    / "private"
    / "stage389-timestamps"
    / "opentimestamps"
)

OTS_WORK_TARGET_PATH = (
    OTS_PRIVATE_DIR
    / "stage388_evidence_manifest.json"
)

OTS_PROOF_PATH = Path(
    str(OTS_WORK_TARGET_PATH)
    + ".ots"
)


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def sha256_file(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def run_command(command):
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )

    output = (
        completed.stdout
        + completed.stderr
    )

    return {
        "command": command,
        "exit_code": completed.returncode,
        "output": output,
        "output_sha256": hashlib.sha256(
            output.encode(
                "utf-8"
            )
        ).hexdigest(),
    }


def semantic_verification_sha256(data):
    canonical = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        canonical
    ).hexdigest()


def discover_ca_file():
    override = os.getenv(
        "STAGE389_RFC3161_CA_FILE"
    )

    if override:
        path = Path(
            override
        )

        if path.is_file():
            return path

    candidates = [
        Path(
            "/etc/ssl/cert.pem"
        ),
        Path(
            "/etc/ssl/certs/"
            "ca-certificates.crt"
        ),
        Path(
            "/opt/homebrew/etc/"
            "openssl@3/cert.pem"
        ),
    ]

    for path in candidates:
        if path.is_file():
            return path

    return None


def verify_rfc3161(
    expected_manifest_sha,
):
    result = {
        "proof_present": False,
        "cryptographic_verification_attempted": False,
        "verification_exit_code": None,
        "semantic_verification_sha256": None,
        "message_imprint_matches_subject": False,
        "tsa_signature_verified": False,
        "certificate_chain_verified": False,
        "rfc3161_verified": False,
        "status": "not_generated",
        "failure": None,
    }

    if not RFC3161_RESPONSE_PATH.is_file():
        return result

    result[
        "proof_present"
    ] = True

    result[
        "status"
    ] = "present_unverified"

    if sha256_file(
        STAGE388_MANIFEST
    ) != expected_manifest_sha:
        result[
            "failure"
        ] = (
            "stage388_manifest_changed_"
            "before_rfc3161_verification"
        )

        result[
            "status"
        ] = "invalid"

        return result

    ca_file = discover_ca_file()

    if ca_file is None:
        result[
            "failure"
        ] = (
            "trusted_ca_file_not_found"
        )

        result[
            "status"
        ] = "verification_unavailable"

        return result

    with tempfile.TemporaryDirectory(
        prefix="stage389-rfc3161-"
    ) as tmp_name:
        tmp_dir = Path(
            tmp_name
        )

        token_path = (
            tmp_dir
            / "token.p7s"
        )

        certs_path = (
            tmp_dir
            / "certs.pem"
        )

        token_result = run_command(
            [
                "openssl",
                "ts",
                "-reply",
                "-in",
                str(
                    RFC3161_RESPONSE_PATH
                ),
                "-token_out",
                "-out",
                str(
                    token_path
                ),
            ]
        )

        if (
            token_result[
                "exit_code"
            ]
            != 0
            or not token_path.is_file()
            or token_path.stat().st_size
            == 0
        ):
            result[
                "failure"
            ] = (
                "rfc3161_token_"
                "extraction_failed"
            )

            result[
                "status"
            ] = "invalid"

            return result

        cert_result = run_command(
            [
                "openssl",
                "pkcs7",
                "-inform",
                "DER",
                "-in",
                str(
                    token_path
                ),
                "-print_certs",
                "-out",
                str(
                    certs_path
                ),
            ]
        )

        if (
            cert_result[
                "exit_code"
            ]
            != 0
            or not certs_path.is_file()
            or certs_path.stat().st_size
            == 0
        ):
            result[
                "failure"
            ] = (
                "rfc3161_certificate_"
                "extraction_failed"
            )

            result[
                "status"
            ] = "invalid"

            return result

        verification = run_command(
            [
                "openssl",
                "ts",
                "-verify",
                "-data",
                str(
                    STAGE388_MANIFEST
                ),
                "-in",
                str(
                    RFC3161_RESPONSE_PATH
                ),
                "-CAfile",
                str(
                    ca_file
                ),
                "-untrusted",
                str(
                    certs_path
                ),
            ]
        )

        result[
            "cryptographic_verification_attempted"
        ] = True

        result[
            "verification_exit_code"
        ] = verification[
            "exit_code"
        ]

        verification_ok = (
            verification[
                "exit_code"
            ]
            == 0
            and "Verification: OK"
            in verification[
                "output"
            ]
        )

        result[
            "message_imprint_matches_subject"
        ] = verification_ok

        result[
            "tsa_signature_verified"
        ] = verification_ok

        result[
            "certificate_chain_verified"
        ] = verification_ok

        result[
            "rfc3161_verified"
        ] = verification_ok

        semantic_state = {
            "proof_present":
                result[
                    "proof_present"
                ],

            "cryptographic_verification_attempted":
                result[
                    "cryptographic_verification_attempted"
                ],

            "verification_exit_code":
                result[
                    "verification_exit_code"
                ],

            "message_imprint_matches_subject":
                result[
                    "message_imprint_matches_subject"
                ],

            "tsa_signature_verified":
                result[
                    "tsa_signature_verified"
                ],

            "certificate_chain_verified":
                result[
                    "certificate_chain_verified"
                ],

            "rfc3161_verified":
                result[
                    "rfc3161_verified"
                ],
        }

        result[
            "semantic_verification_sha256"
        ] = semantic_verification_sha256(
            semantic_state
        )

        if verification_ok:
            result[
                "status"
            ] = "verified"
        else:
            result[
                "status"
            ] = "invalid"

            result[
                "failure"
            ] = (
                "openssl_ts_verify_failed"
            )

    return result


def verify_opentimestamps(
    expected_manifest_sha,
):
    result = {
        "work_target_present": False,
        "proof_present": False,
        "target_matches_subject": False,
        "cryptographic_verification_attempted": False,
        "verification_exit_code": None,
        "semantic_verification_sha256": None,
        "bitcoin_attestation_present": False,
        "bitcoin_confirmation_verified": False,
        "opentimestamps_verified": False,
        "status": "not_generated",
        "failure": None,
    }

    target_exists = (
        OTS_WORK_TARGET_PATH.is_file()
    )

    proof_exists = (
        OTS_PROOF_PATH.is_file()
    )

    result[
        "work_target_present"
    ] = target_exists

    result[
        "proof_present"
    ] = proof_exists

    if not target_exists and not proof_exists:
        return result

    if target_exists != proof_exists:
        result[
            "status"
        ] = "invalid"

        result[
            "failure"
        ] = (
            "incomplete_opentimestamps_"
            "proof_material"
        )

        return result

    actual_target_sha = sha256_file(
        OTS_WORK_TARGET_PATH
    )

    target_matches = (
        actual_target_sha
        == expected_manifest_sha
        and sha256_file(
            STAGE388_MANIFEST
        )
        == expected_manifest_sha
    )

    result[
        "target_matches_subject"
    ] = target_matches

    if not target_matches:
        result[
            "status"
        ] = "invalid"

        result[
            "failure"
        ] = (
            "opentimestamps_target_"
            "hash_mismatch"
        )

        return result

    verification = run_command(
        [
            "ots",
            "verify",
            str(
                OTS_PROOF_PATH
            ),
        ]
    )

    result[
        "cryptographic_verification_attempted"
    ] = True

    result[
        "verification_exit_code"
    ] = verification[
        "exit_code"
    ]

    output_lower = (
        verification[
            "output"
        ].lower()
    )

    bitcoin_success = (
        verification[
            "exit_code"
        ]
        == 0
        and "success!"
        in output_lower
        and "bitcoin"
        in output_lower
    )

    pending = (
        "pending confirmation"
        in output_lower
        or "pending"
        in output_lower
    )

    local_bitcoin_chain_incomplete = (
        "bitcoin block height"
        in output_lower
        and "not found"
        in output_lower
        and "highest known block"
        in output_lower
    )

    result[
        "bitcoin_attestation_present"
    ] = bitcoin_success

    result[
        "bitcoin_confirmation_verified"
    ] = bitcoin_success

    result[
        "opentimestamps_verified"
    ] = bitcoin_success

    if bitcoin_success:
        result[
            "status"
        ] = "verified"

    elif pending:
        result[
            "status"
        ] = "pending_confirmation"

    elif local_bitcoin_chain_incomplete:
        result[
            "status"
        ] = "verification_incomplete"

        result[
            "failure"
        ] = None

        result[
            "verification_incomplete_reason"
        ] = (
            "local_bitcoin_chain_data_unavailable"
        )

    else:
        result[
            "status"
        ] = "invalid"

        result[
            "failure"
        ] = (
            "ots_verify_failed"
        )


    semantic_state = {
        "work_target_present":
            result["work_target_present"],

        "proof_present":
            result["proof_present"],

        "target_matches_subject":
            result["target_matches_subject"],

        "cryptographic_verification_attempted":
            result[
                "cryptographic_verification_attempted"
            ],

        "verification_exit_code":
            result["verification_exit_code"],

        "bitcoin_attestation_present":
            result["bitcoin_attestation_present"],

        "bitcoin_confirmation_verified":
            result["bitcoin_confirmation_verified"],

        "opentimestamps_verified":
            result["opentimestamps_verified"],

        "status":
            result["status"],

        "verification_incomplete_reason":
            result.get(
                "verification_incomplete_reason"
            ),
    }

    result[
        "semantic_verification_sha256"
    ] = semantic_verification_sha256(
        semantic_state
    )

    return result


def main():
    failures = []

    required_public_files = [
        STAGE388_MANIFEST,
        CONTRACT_PATH,
        POLICY_PATH,
        RFC3161_METADATA_PATH,
        OTS_METADATA_PATH,
    ]

    for path in required_public_files:
        if not path.is_file():
            failures.append(
                "required file missing: "
                + str(
                    path.relative_to(
                        ROOT
                    )
                )
            )

    if failures:
        print(
            json.dumps(
                {
                    "schema_version":
                        "1.0",
                    "stage":
                        389,
                    "decision":
                        "fail_closed",
                    "verification_status":
                        "failed",
                    "critical_failure_count":
                        len(
                            failures
                        ),
                    "failures":
                        failures,
                },
                indent=2,
                sort_keys=True,
            )
        )

        return 1

    contract = read_json(
        CONTRACT_PATH
    )

    policy = read_json(
        POLICY_PATH
    )

    manifest = read_json(
        STAGE388_MANIFEST
    )

    rfc_metadata = read_json(
        RFC3161_METADATA_PATH
    )

    ots_metadata = read_json(
        OTS_METADATA_PATH
    )

    expected_manifest_sha = (
        contract[
            "timestamp_subject"
        ][
            "sha256"
        ]
    )

    expected_target_path = (
        contract[
            "timestamp_subject"
        ][
            "path"
        ]
    )

    actual_manifest_sha = sha256_file(
        STAGE388_MANIFEST
    )

    expected_package_sha = (
        contract[
            "bound_stage388_package"
        ][
            "canonical_package_sha256"
        ]
    )

    expected_entry_count = (
        contract[
            "bound_stage388_package"
        ][
            "canonical_entry_count"
        ]
    )

    checks = {}

    checks[
        "stage_number_valid"
    ] = (
        contract.get(
            "stage"
        )
        == 389
        and policy.get(
            "stage"
        )
        == 389
    )

    checks[
        "source_stage_valid"
    ] = (
        contract.get(
            "source_stage"
        )
        == 388
        and policy.get(
            "source_stage"
        )
        == 388
    )

    checks[
        "stage388_manifest_sha256_matches"
    ] = (
        actual_manifest_sha
        == expected_manifest_sha
    )

    checks[
        "stage388_canonical_package_sha256_matches"
    ] = (
        manifest.get(
            "canonical_package_sha256"
        )
        == expected_package_sha
    )

    checks[
        "stage388_entry_count_matches"
    ] = (
        manifest.get(
            "entry_count"
        )
        == expected_entry_count
    )

    rfc_subject = (
        rfc_metadata.get(
            "timestamp_subject",
            {},
        )
    )

    ots_subject = (
        ots_metadata.get(
            "timestamp_subject",
            {},
        )
    )

    checks[
        "rfc3161_subject_matches_contract"
    ] = (
        rfc_subject.get(
            "path"
        )
        == expected_target_path
        and rfc_subject.get(
            "sha256"
        )
        == expected_manifest_sha
    )

    checks[
        "opentimestamps_subject_matches_contract"
    ] = (
        ots_subject.get(
            "path"
        )
        == expected_target_path
        and ots_subject.get(
            "sha256"
        )
        == expected_manifest_sha
    )

    checks[
        "same_timestamp_target"
    ] = (
        rfc_subject.get(
            "path"
        )
        == ots_subject.get(
            "path"
        )
        == expected_target_path
        and rfc_subject.get(
            "sha256"
        )
        == ots_subject.get(
            "sha256"
        )
        == expected_manifest_sha
    )

    invariant_checks = [
        "stage_number_valid",
        "source_stage_valid",
        "stage388_manifest_sha256_matches",
        "stage388_canonical_package_sha256_matches",
        "stage388_entry_count_matches",
        "rfc3161_subject_matches_contract",
        "opentimestamps_subject_matches_contract",
        "same_timestamp_target",
    ]

    for name in invariant_checks:
        if not checks[
            name
        ]:
            failures.append(
                name
            )

    rfc_result = verify_rfc3161(
        expected_manifest_sha
    )

    ots_result = (
        verify_opentimestamps(
            expected_manifest_sha
        )
    )

    if rfc_result[
        "failure"
    ] is not None:
        failures.append(
            "rfc3161:"
            + rfc_result[
                "failure"
            ]
        )

    if ots_result[
        "failure"
    ] is not None:
        failures.append(
            "opentimestamps:"
            + ots_result[
                "failure"
            ]
        )

    checks[
        "rfc3161_proof_present"
    ] = rfc_result[
        "proof_present"
    ]

    checks[
        "rfc3161_cryptographic_verification_attempted"
    ] = rfc_result[
        "cryptographic_verification_attempted"
    ]

    checks[
        "rfc3161_verified"
    ] = rfc_result[
        "rfc3161_verified"
    ]

    checks[
        "opentimestamps_proof_present"
    ] = ots_result[
        "proof_present"
    ]

    checks[
        "opentimestamps_cryptographic_verification_attempted"
    ] = ots_result[
        "cryptographic_verification_attempted"
    ]

    checks[
        "opentimestamps_verified"
    ] = ots_result[
        "opentimestamps_verified"
    ]

    checks[
        "dual_timestamp_verified"
    ] = (
        checks[
            "rfc3161_verified"
        ]
        and checks[
            "opentimestamps_verified"
        ]
        and checks[
            "same_timestamp_target"
        ]
    )

    if failures:
        decision = (
            contract[
                "fail_closed_decision"
            ]
        )

        verification_status = (
            "failed"
        )

    elif checks[
        "dual_timestamp_verified"
    ]:
        decision = (
            contract[
                "success_decision"
            ]
        )

        verification_status = (
            "verified"
        )

    else:
        decision = (
            contract[
                "pending_decision"
            ]
        )

        verification_status = (
            "pending_external_confirmation"
        )

    result = {
        "schema_version": "1.0",
        "stage": 389,
        "engine": (
            "independent_assessment_package_"
            "dual_external_timestamp_gate"
        ),
        "source_stage": 388,
        "timestamp_subject": {
            "path":
                expected_target_path,
            "sha256":
                expected_manifest_sha,
        },
        "bound_stage388_package": {
            "canonical_package_sha256":
                expected_package_sha,
            "canonical_entry_count":
                expected_entry_count,
            "source_commit":
                contract[
                    "bound_stage388_package"
                ][
                    "source_commit"
                ],
        },
        "checks": checks,

        # These metadata claims are deliberately
        # reported but NEVER trusted as proof.
        "declared_evidence_metadata": {
            "rfc3161": {
                "evidence_status":
                    rfc_metadata.get(
                        "evidence_status"
                    ),
                "declared_rfc3161_verified":
                    rfc_metadata.get(
                        "rfc3161_verified"
                    ),
            },
            "opentimestamps": {
                "evidence_status":
                    ots_metadata.get(
                        "evidence_status"
                    ),
                "declared_opentimestamps_verified":
                    ots_metadata.get(
                        "opentimestamps_verified"
                    ),
            },
        },

        "derived_external_verification": {
            "rfc3161":
                rfc_result,
            "opentimestamps":
                ots_result,
        },

        "dual_timestamp_verified":
            checks[
                "dual_timestamp_verified"
            ],

        "decision":
            decision,

        "verification_status":
            verification_status,

        "critical_failure_count":
            len(
                failures
            ),

        "failures":
            failures,

        "limitations": {
            "external_assessment_completed":
                False,
            "formal_certification":
                False,
            "system_wide_formal_acceptance":
                False,
            "entire_system_quantum_safe":
                False,
        },
    }

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    if failures:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )
