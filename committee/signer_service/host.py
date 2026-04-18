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


def main() -> None:
    payload = json.load(sys.stdin)
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
