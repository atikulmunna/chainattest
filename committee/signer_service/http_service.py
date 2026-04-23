from __future__ import annotations

import json
import os
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from coordinator.chainattest_coordinator.audit import AuditLogger
from committee.signer_service.signer import (
    ApprovalRequest,
    BRIDGE_ENTRYPOINT,
    CommitteeSigner,
    EvalAttestationRequest,
)


def _require_env(env_name: str) -> str:
    value = os.environ.get(env_name)
    if value is None:
        raise ServiceError("missing_secret_env", f"required signer environment variable is missing: {env_name}")
    return value


def _load_policy() -> dict[str, set[str]]:
    policy_path = os.environ.get("CHAINATTEST_SIGNER_POLICY_PATH", "").strip()
    if not policy_path:
        return {}
    raw = json.loads(Path(policy_path).read_text())
    policy: dict[str, set[str]] = {}
    for key, values in raw.items():
        if not isinstance(values, list):
            continue
        policy[key] = {str(value).strip().lower() for value in values if str(value).strip()}
    return policy


def _build_audit_logger() -> AuditLogger | None:
    audit_path = os.environ.get("CHAINATTEST_SIGNER_AUDIT_LOG", "").strip()
    if not audit_path:
        return None
    return AuditLogger(Path(audit_path))


def _wallet_address(private_key: str) -> str:
    result = subprocess.run(
        ["node", str(BRIDGE_ENTRYPOINT)],
        input=json.dumps({"action": "wallet_address", "privateKey": private_key}),
        text=True,
        capture_output=True,
        check=True,
        cwd=Path(__file__).resolve().parents[2],
    )
    return json.loads(result.stdout)["address"]


class ServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = int(status_code)


@dataclass
class SignerServiceState:
    auth_token: str | None
    replay_window_seconds: int
    audit_logger: AuditLogger | None
    policy: dict[str, set[str]]
    seen_nonces: dict[str, int]

    def purge_expired_nonces(self) -> None:
        cutoff = int(time.time()) - self.replay_window_seconds
        expired = [nonce for nonce, timestamp in self.seen_nonces.items() if timestamp < cutoff]
        for nonce in expired:
            self.seen_nonces.pop(nonce, None)

    def verify_request(self, headers, action: str) -> tuple[int, str]:
        self._verify_auth(headers)
        timestamp = self._verify_freshness(headers)
        return timestamp, headers.get("X-ChainAttest-Nonce", "")

    def _verify_auth(self, headers) -> None:
        if self.auth_token is None:
            return
        authorization = headers.get("Authorization", "")
        expected = f"Bearer {self.auth_token}"
        if authorization != expected:
            raise ServiceError("auth_failed", "signer service authentication failed", HTTPStatus.UNAUTHORIZED)

    def _verify_freshness(self, headers) -> int:
        raw_timestamp = headers.get("X-ChainAttest-Timestamp")
        nonce = headers.get("X-ChainAttest-Nonce")
        if raw_timestamp is None or nonce is None:
            raise ServiceError("bad_request", "timestamp and nonce headers are required")
        try:
            timestamp = int(raw_timestamp)
        except ValueError as error:
            raise ServiceError("bad_request", "timestamp header must be an integer") from error

        self.purge_expired_nonces()
        now = int(time.time())
        if abs(now - timestamp) > self.replay_window_seconds:
            raise ServiceError("stale_request", "request timestamp is outside the allowed replay window")
        if nonce in self.seen_nonces:
            raise ServiceError("replay_rejected", "request nonce has already been used", HTTPStatus.CONFLICT)
        self.seen_nonces[nonce] = timestamp
        return timestamp

    def enforce_policy(self, action: str, payload: dict[str, Any]) -> None:
        self._require_policy_match("allowed_actions", action, "action")
        destination_chain = payload.get("destinationChainId")
        if destination_chain is not None:
            self._require_policy_match(
                "allowed_destination_chains",
                str(destination_chain),
                "destination chain",
            )
        verifier = payload.get("verifierAddress")
        if verifier is not None:
            self._require_policy_match("allowed_verifiers", verifier, "verifier")
        package_kind = payload.get("packageKind")
        if package_kind is not None:
            self._require_policy_match("allowed_package_kinds", package_kind, "package kind")
        package = payload.get("package", {})
        evaluator = package.get("evaluator")
        if evaluator is not None:
            self._require_policy_match("allowed_evaluators", evaluator, "evaluator")
        private_key_env = payload.get("privateKeyEnv")
        if private_key_env is not None and action == "submit_destination_package":
            submitter_address = _wallet_address(_require_env(private_key_env))
            self._require_policy_match("allowed_submitters", submitter_address, "submitter")

    def audit(self, event_type: str, payload: dict[str, Any]) -> None:
        if self.audit_logger is None:
            return
        self.audit_logger.log(event_type, payload)

    def _require_policy_match(self, key: str, value: str, label: str) -> None:
        allowed = self.policy.get(key)
        if allowed and value.lower() not in allowed:
            raise ServiceError("policy_rejected", f"signer service policy rejected {label}: {value}", HTTPStatus.FORBIDDEN)


class SignerHttpHandler(BaseHTTPRequestHandler):
    server_version = "ChainAttestSigner/1.0"

    @property
    def state(self) -> SignerServiceState:
        return self.server.state  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._respond_error(ServiceError("not_found", "unknown route", HTTPStatus.NOT_FOUND))
            return
        self._respond_json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "service": "chainattest-signer",
                "queueDepth": 0,
                "replayWindowSeconds": self.state.replay_window_seconds,
                "policyLoaded": bool(self.state.policy),
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        routes = {
            "/approve": "approve",
            "/sign-eval": "sign_eval_attestation",
            "/submit": "submit_destination_package",
        }
        action = routes.get(self.path)
        if action is None:
            self._respond_error(ServiceError("not_found", "unknown route", HTTPStatus.NOT_FOUND))
            return

        try:
            payload = self._read_json()
            timestamp, nonce = self.state.verify_request(self.headers, action)
            summary = self._summary(action, payload, timestamp, nonce)
            self.state.audit("signer_http_request_received", summary)
            self.state.enforce_policy(action, payload)
            response = self._dispatch(action, payload)
            self.state.audit("signer_http_request_completed", {**summary, "result": self._result_summary(response)})
            self._respond_json(HTTPStatus.OK, response)
        except ServiceError as error:
            self.state.audit(
                "signer_http_request_rejected",
                {
                    "route": self.path,
                    "error_code": error.code,
                    "message": error.message,
                },
            )
            self._respond_error(error)
        except Exception as error:  # pragma: no cover - safety net
            self.state.audit(
                "signer_http_request_failed",
                {
                    "route": self.path,
                    "error_code": "internal_error",
                    "message": str(error),
                },
            )
            self._respond_error(
                ServiceError(
                    "internal_error",
                    str(error),
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
            )

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _read_json(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ServiceError("bad_request", "request body is required")
        return json.loads(self.rfile.read(content_length).decode("utf-8"))

    def _dispatch(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action == "approve":
            private_keys = [_require_env(env_name) for env_name in payload["committeeKeyEnvs"]]
            signer = CommitteeSigner(private_keys)
            return signer.approve(
                ApprovalRequest(
                    package=payload["package"],
                    destination_chain_id=int(payload["destinationChainId"]),
                    verifier_address=payload["verifierAddress"],
                    threshold=payload.get("threshold"),
                )
            )

        if action == "sign_eval_attestation":
            signer = CommitteeSigner([])
            return signer.sign_eval_attestation(
                EvalAttestationRequest(
                    package=payload["package"],
                    destination_chain_id=int(payload["destinationChainId"]),
                    verifier_address=payload["verifierAddress"],
                    private_key=_require_env(payload["privateKeyEnv"]),
                )
            )

        if action == "submit_destination_package":
            signer = CommitteeSigner([])
            return signer._run_bridge(
                {
                    "action": "submit_destination_package",
                    "rpcUrl": payload["rpcUrl"],
                    "privateKey": _require_env(payload["privateKeyEnv"]),
                    "verifierAddress": payload["verifierAddress"],
                    "packageKind": payload["packageKind"],
                    "package": payload["package"],
                }
            )

        raise ServiceError("unsupported_action", f"unsupported action: {action}")

    def _summary(self, action: str, payload: dict[str, Any], timestamp: int, nonce: str) -> dict[str, Any]:
        package = payload.get("package", {})
        summary = {
            "action": action,
            "timestamp": timestamp,
            "nonce": nonce,
            "destination_chain_id": payload.get("destinationChainId"),
            "verifier_address": payload.get("verifierAddress"),
            "package_kind": payload.get("packageKind"),
            "attestation_id": package.get("attestationId"),
            "package_type": package.get("packageType"),
            "evaluator": package.get("evaluator"),
        }
        private_key_env = payload.get("privateKeyEnv")
        if private_key_env is not None:
            summary["signer_env"] = private_key_env
        return summary

    def _result_summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        if "txHash" in payload:
            summary["tx_hash"] = payload["txHash"]
        if "signatures" in payload:
            summary["signature_count"] = len(payload["signatures"])
        if "signerAddress" in payload:
            summary["signer_address"] = payload["signerAddress"]
        return summary

    def _respond_json(self, status_code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _respond_error(self, error: ServiceError) -> None:
        self._respond_json(
            error.status_code,
            {
                "ok": False,
                "error": {
                    "code": error.code,
                    "message": error.message,
                },
            },
        )


def main() -> None:
    host = os.environ.get("CHAINATTEST_SIGNER_HOST", "127.0.0.1")
    port = int(os.environ.get("CHAINATTEST_SIGNER_PORT", "8787"))
    state = SignerServiceState(
        auth_token=os.environ.get("CHAINATTEST_SIGNER_AUTH_TOKEN"),
        replay_window_seconds=int(os.environ.get("CHAINATTEST_SIGNER_REPLAY_WINDOW_SECONDS", "60")),
        audit_logger=_build_audit_logger(),
        policy=_load_policy(),
        seen_nonces={},
    )
    server = ThreadingHTTPServer((host, port), SignerHttpHandler)
    server.state = state  # type: ignore[attr-defined]
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
