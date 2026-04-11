from dataclasses import dataclass


@dataclass
class ApprovalRequest:
    source_chain_id: int
    source_registry: str
    attestation_id: int
    message_type: str


class CommitteeSigner:
    def approve(self, request: ApprovalRequest) -> dict:
        return {
            "approved": True,
            "reason": "scaffold only",
            "attestation_id": request.attestation_id,
            "message_type": request.message_type,
        }

