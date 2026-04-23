from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request
from uuid import uuid4


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


@dataclass
class CommandApprovalRequest:
    package: dict
    destination_chain_id: int
    verifier_address: str
    committee_key_envs: list[str]
    threshold: int | None = None


@dataclass
class CommandEvalAttestationRequest:
    package: dict
    destination_chain_id: int
    verifier_address: str
    private_key_env: str


@dataclass
class CommandSubmissionRequest:
    package: dict
    package_kind: str
    destination_rpc_url: str
    destination_verifier_address: str
    submitter_key_env: str


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


class HttpSignerClient:
    def __init__(
        self,
        base_url: str,
        auth_token_env: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_token_env = auth_token_env
        self.timeout_seconds = timeout_seconds

    def health(self) -> dict:
        return self._request("GET", "/health")

    def approve(self, request: CommandApprovalRequest) -> dict:
        payload = {
            "destinationChainId": request.destination_chain_id,
            "verifierAddress": request.verifier_address,
            "committeeKeyEnvs": request.committee_key_envs,
            "threshold": request.threshold,
            "package": request.package,
        }
        return self._request("POST", "/approve", payload)

    def sign_eval_attestation(self, request: CommandEvalAttestationRequest) -> dict:
        payload = {
            "destinationChainId": request.destination_chain_id,
            "verifierAddress": request.verifier_address,
            "privateKeyEnv": request.private_key_env,
            "package": request.package,
        }
        return self._request("POST", "/sign-eval", payload)

    def submit_package(self, request: CommandSubmissionRequest) -> dict:
        payload = {
            "rpcUrl": request.destination_rpc_url,
            "verifierAddress": request.destination_verifier_address,
            "packageKind": request.package_kind,
            "privateKeyEnv": request.submitter_key_env,
            "package": request.package,
        }
        return self._request("POST", "/submit", payload)

    def _request(self, method: str, route: str, payload: dict | None = None) -> dict:
        headers = {
            "Accept": "application/json",
            "X-ChainAttest-Timestamp": str(int(time.time())),
            "X-ChainAttest-Nonce": uuid4().hex,
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        else:
            body = None
        if self.auth_token_env is not None:
            auth_token = os.environ.get(self.auth_token_env)
            if auth_token is None:
                raise ValueError(f"required signer auth token env is missing: {self.auth_token_env}")
            headers["Authorization"] = f"Bearer {auth_token}"

        request = urllib_request.Request(
            f"{self.base_url}{route}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib_request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode())
        except urllib_error.HTTPError as error:
            try:
                payload = json.loads(error.read().decode())
            except Exception:
                payload = {}
            details = payload.get("error", {})
            code = details.get("code", f"http_{error.code}")
            message = details.get("message", str(error))
            raise RuntimeError(f"{code}: {message}") from error
        except urllib_error.URLError as error:
            raise RuntimeError(f"signer_transport_error: {error}") from error


class CommandSignerClient:
    def __init__(self, command: Sequence[str], auth_token_env: str | None = None) -> None:
        if not command:
            raise ValueError("signer command is required")
        self.command = list(command)
        self.auth_token_env = auth_token_env

    def approve(self, request: CommandApprovalRequest) -> dict:
        payload = {
            "action": "approve",
            "destinationChainId": request.destination_chain_id,
            "verifierAddress": request.verifier_address,
            "committeeKeyEnvs": request.committee_key_envs,
            "threshold": request.threshold,
            "package": request.package,
        }
        return self._run_command(payload)

    def sign_eval_attestation(self, request: CommandEvalAttestationRequest) -> dict:
        payload = {
            "action": "sign_eval_attestation",
            "destinationChainId": request.destination_chain_id,
            "verifierAddress": request.verifier_address,
            "privateKeyEnv": request.private_key_env,
            "package": request.package,
        }
        return self._run_command(payload)

    def submit_package(self, request: CommandSubmissionRequest) -> dict:
        payload = {
            "action": "submit_destination_package",
            "rpcUrl": request.destination_rpc_url,
            "verifierAddress": request.destination_verifier_address,
            "packageKind": request.package_kind,
            "privateKeyEnv": request.submitter_key_env,
            "package": request.package,
        }
        return self._run_command(payload)

    def _run_command(self, payload: dict) -> dict:
        if self.auth_token_env is not None:
            auth_token = os.environ.get(self.auth_token_env)
            if auth_token is None:
                raise ValueError(f"required signer auth token env is missing: {self.auth_token_env}")
            payload = {
                **payload,
                "authToken": auth_token,
            }
        try:
            result = subprocess.run(
                self.command,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                check=True,
                cwd=REPO_ROOT,
            )
        except subprocess.CalledProcessError as error:
            message = (error.stderr or error.stdout or str(error)).strip()
            raise RuntimeError(message) from error
        return json.loads(result.stdout)
