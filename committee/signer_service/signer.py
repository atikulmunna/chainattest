from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[2]
BRIDGE_ENTRYPOINT = REPO_ROOT / "cli" / "chain_attest" / "crypto_bridge.js"


@dataclass
class ApprovalRequest:
    package: dict
    destination_chain_id: int
    verifier_address: str
    threshold: int | None = None


@dataclass
class EvalAttestationRequest:
    package: dict
    destination_chain_id: int
    verifier_address: str
    private_key: str


class CommitteeSigner:
    def __init__(self, private_keys: list[str]) -> None:
        self.private_keys = private_keys

    def approve(self, request: ApprovalRequest) -> dict:
        if not self.private_keys:
            raise ValueError("committee private keys are required")
        payload = {
            "action": "sign_committee_package",
            "chainId": str(request.destination_chain_id),
            "verifyingContract": request.verifier_address,
            "privateKeys": self.private_keys,
            "threshold": request.threshold,
            "package": request.package,
        }
        return self._run_bridge(payload)

    def sign_eval_attestation(self, request: EvalAttestationRequest) -> dict:
        payload = {
            "action": "sign_eval_package",
            "chainId": str(request.destination_chain_id),
            "verifyingContract": request.verifier_address,
            "privateKey": request.private_key,
            "package": request.package,
        }
        return self._run_bridge(payload)

    def _run_bridge(self, payload: dict) -> dict:
        result = subprocess.run(
            ["node", str(BRIDGE_ENTRYPOINT)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
            cwd=REPO_ROOT,
        )
        return json.loads(result.stdout)
