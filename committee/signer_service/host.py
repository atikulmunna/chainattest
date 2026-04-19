from __future__ import annotations

import json
import os
from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from committee.signer_service.signer import ApprovalRequest, CommitteeSigner, EvalAttestationRequest


def _require_env(env_name: str) -> str:
    value = os.environ.get(env_name)
    if value is None:
        raise ValueError(f"required signer environment variable is missing: {env_name}")
    return value


def _parse_csv_env(env_name: str) -> set[str]:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return set()
    return {value.strip().lower() for value in raw.split(",") if value.strip()}


def _verify_auth(payload: dict) -> None:
    expected = os.environ.get("CHAINATTEST_SIGNER_AUTH_TOKEN")
    if expected is None:
        return
    provided = payload.get("authToken")
    if provided != expected:
        raise PermissionError("signer host authentication failed")


def _enforce_policy(payload: dict) -> None:
    allowed_actions = _parse_csv_env("CHAINATTEST_SIGNER_ALLOWED_ACTIONS")
    if allowed_actions and payload["action"].lower() not in allowed_actions:
        raise PermissionError(f"signer host policy rejected action: {payload['action']}")

    allowed_verifiers = _parse_csv_env("CHAINATTEST_SIGNER_ALLOWED_VERIFIERS")
    verifier = payload.get("verifierAddress")
    if allowed_verifiers and verifier and verifier.lower() not in allowed_verifiers:
        raise PermissionError(f"signer host policy rejected verifier: {verifier}")

    allowed_package_kinds = _parse_csv_env("CHAINATTEST_SIGNER_ALLOWED_PACKAGE_KINDS")
    package_kind = payload.get("packageKind")
    if allowed_package_kinds and package_kind and package_kind.lower() not in allowed_package_kinds:
        raise PermissionError(f"signer host policy rejected package kind: {package_kind}")

    allowed_destination_chains = _parse_csv_env("CHAINATTEST_SIGNER_ALLOWED_DESTINATION_CHAINS")
    destination_chain = payload.get("destinationChainId")
    if allowed_destination_chains and destination_chain is not None:
        if str(destination_chain).lower() not in allowed_destination_chains:
            raise PermissionError(
                f"signer host policy rejected destination chain: {destination_chain}"
            )


def main() -> None:
    payload = json.load(sys.stdin)
    _verify_auth(payload)
    _enforce_policy(payload)
    action = payload["action"]

    if action == "approve":
        private_keys = [_require_env(env_name) for env_name in payload["committeeKeyEnvs"]]
        signer = CommitteeSigner(private_keys)
        response = signer.approve(
            ApprovalRequest(
                package=payload["package"],
                destination_chain_id=int(payload["destinationChainId"]),
                verifier_address=payload["verifierAddress"],
                threshold=payload.get("threshold"),
            )
        )
        json.dump(response, sys.stdout)
        return

    if action == "sign_eval_attestation":
        private_key = _require_env(payload["privateKeyEnv"])
        signer = CommitteeSigner([])
        response = signer.sign_eval_attestation(
            EvalAttestationRequest(
                package=payload["package"],
                destination_chain_id=int(payload["destinationChainId"]),
                verifier_address=payload["verifierAddress"],
                private_key=private_key,
            )
        )
        json.dump(response, sys.stdout)
        return

    if action == "submit_destination_package":
        private_key = _require_env(payload["privateKeyEnv"])
        signer = CommitteeSigner([])
        response = signer._run_bridge(
            {
                "action": "submit_destination_package",
                "rpcUrl": payload["rpcUrl"],
                "privateKey": private_key,
                "verifierAddress": payload["verifierAddress"],
                "packageKind": payload["packageKind"],
                "package": payload["package"],
            }
        )
        json.dump(response, sys.stdout)
        return

    raise ValueError(f"unsupported host action: {action}")


if __name__ == "__main__":
    main()
