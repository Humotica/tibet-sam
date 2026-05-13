from __future__ import annotations

from dataclasses import asdict, dataclass, field


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
            "events": [event.to_dict() for event in self.events],
        }
