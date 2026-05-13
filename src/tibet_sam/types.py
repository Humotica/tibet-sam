from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class SAMConstraint:
    key: str
    value: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SAMRecord:
    sam_id: str
    intent: str
    secret_id: str
    target_action: str
    actor_id: str
    valid_until: str
    ephemeral_id: str
    policy_lane: str | None = None
    receipt_required: bool = True
    supersedes_sam_id: str | None = None
    upstream_url: str | None = None
    upstream_method: str | None = None
    upstream_payload: dict[str, Any] = field(default_factory=dict)
    constraints: list[SAMConstraint] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sam_id": self.sam_id,
            "intent": self.intent,
            "secret_id": self.secret_id,
            "target_action": self.target_action,
            "actor_id": self.actor_id,
            "valid_until": self.valid_until,
            "ephemeral_id": self.ephemeral_id,
            "policy_lane": self.policy_lane,
            "receipt_required": self.receipt_required,
            "supersedes_sam_id": self.supersedes_sam_id,
            "upstream_url": self.upstream_url,
            "upstream_method": self.upstream_method,
            "upstream_payload": dict(self.upstream_payload),
            "constraints": [constraint.to_dict() for constraint in self.constraints],
            "notes": list(self.notes),
        }


@dataclass
class SAMGatewayEvent:
    action: str
    status: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SAMGatewayResponse:
    sam_id: str
    ephemeral_id: str
    requested_action: str
    executed_action: str | None
    status: str
    gateway_actor: str
    executed_at: str
    result_summary: str
    policy_verdict: str
    destroy_session_confirmed: bool
    policy_lane: str | None = None
    receipt_required: bool = True
    runtime_adapter: str | None = None
    events: list[SAMGatewayEvent] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sam_id": self.sam_id,
            "ephemeral_id": self.ephemeral_id,
            "requested_action": self.requested_action,
            "executed_action": self.executed_action,
            "status": self.status,
            "gateway_actor": self.gateway_actor,
            "executed_at": self.executed_at,
            "result_summary": self.result_summary,
            "policy_verdict": self.policy_verdict,
            "destroy_session_confirmed": self.destroy_session_confirmed,
            "policy_lane": self.policy_lane,
            "receipt_required": self.receipt_required,
            "runtime_adapter": self.runtime_adapter,
            "events": [event.to_dict() for event in self.events],
        }
