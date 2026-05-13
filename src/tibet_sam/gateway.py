from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .keychain_bridge import validate_keychain_binding
from .materialize import emit_sealed_payload_bundle
from .types import SAMConstraint, SAMGatewayEvent, SAMGatewayResponse, SAMRecord


class SAMGatewayError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _constraint_map(record: SAMRecord) -> dict[str, str]:
    return {constraint.key: constraint.value for constraint in record.constraints}


@dataclass
class GatewaySession:
    session_id: str
    ephemeral_id: str
    gateway_actor: str
    secret_handle: str


@dataclass
class GatewayExecutionResult:
    action: str
    summary: str
    details: list[str]


def _record_from_payload(payload: dict) -> SAMRecord:
    return SAMRecord(
        sam_id=payload["sam_id"],
        intent=payload["intent"],
        secret_id=payload["secret_id"],
        target_action=payload["target_action"],
        actor_id=payload["actor_id"],
        valid_until=payload["valid_until"],
        ephemeral_id=payload["ephemeral_id"],
        policy_lane=payload.get("policy_lane"),
        receipt_required=bool(payload.get("receipt_required", True)),
        supersedes_sam_id=payload.get("supersedes_sam_id"),
        upstream_url=payload.get("upstream_url"),
        upstream_method=payload.get("upstream_method"),
        upstream_payload=dict(payload.get("upstream_payload") or {}),
        constraints=[
            SAMConstraint(key=item["key"], value=item["value"])
            for item in payload.get("constraints", [])
        ],
        notes=list(payload.get("notes", [])),
    )


def _load_tibet_drop_bundle():
    try:
        from tibet_drop.bundle import unpack_bundle  # type: ignore
    except ImportError:
        local_src = "/srv/jtel-stack/sandbox/airdrop-cli/src"
        if local_src not in sys.path:
            sys.path.insert(0, local_src)
        from tibet_drop.bundle import unpack_bundle  # type: ignore

    return unpack_bundle


def _load_sam_from_bundle(path: Path) -> SAMRecord:
    unpack_bundle = _load_tibet_drop_bundle()
    with tempfile.TemporaryDirectory(prefix="tibet-sam-unpack-") as tmpdir:
        unpack_bundle(path, Path(tmpdir))
        sam_path = Path(tmpdir) / "sam.json"
        if not sam_path.exists():
            raise SAMGatewayError("sam-bundle-invalid", "bundle does not contain sam.json")
        payload = json.loads(sam_path.read_text(encoding="utf-8"))
    return _record_from_payload(payload)


def load_sam(path: str) -> SAMRecord:
    source = Path(path)
    if source.suffix == ".tza":
        return _load_sam_from_bundle(source)
    payload = json.loads(source.read_text(encoding="utf-8"))
    return _record_from_payload(payload)


def _mock_secret_resolution(secret_id: str) -> str:
    if not secret_id.startswith("sec_"):
        raise SAMGatewayError("sam-secret-unavailable", f"unknown secret id: {secret_id}")
    return f"handle:{secret_id}"


def _validate_policy_lane(record: SAMRecord) -> list[SAMGatewayEvent]:
    events: list[SAMGatewayEvent] = []
    if not record.policy_lane:
        return events
    if record.policy_lane == "publish":
        constraints = _constraint_map(record)
        if "registry" not in constraints:
            raise SAMGatewayError("sam-policy-lane-invalid", "publish lane requires registry constraint")
    if record.policy_lane == "proxy-egress":
        if record.target_action != "/proxy/http" or not record.upstream_url:
            raise SAMGatewayError(
                "sam-policy-lane-invalid",
                "proxy-egress lane requires target_action=/proxy/http and upstream_url",
            )
    events.append(SAMGatewayEvent("sam-policy-lane", "pass", f"policy_lane={record.policy_lane}"))
    return events


def _break_seal_within_runtime(record: SAMRecord, gateway_actor: str) -> tuple[GatewaySession, SAMGatewayEvent]:
    secret_handle = _mock_secret_resolution(record.secret_id)
    session = GatewaySession(
        session_id=f"gsess:{record.ephemeral_id}",
        ephemeral_id=record.ephemeral_id,
        gateway_actor=gateway_actor,
        secret_handle=secret_handle,
    )
    return session, SAMGatewayEvent(
        "sam-session-opened",
        "pass",
        f"session_id={session.session_id}",
    )


def _execute_upload_package(record: SAMRecord, session: GatewaySession) -> GatewayExecutionResult:
    constraints = _constraint_map(record)
    package_name = constraints.get("package", "<unknown>")
    registry = constraints.get("registry", "<unknown>")
    return GatewayExecutionResult(
        action=record.target_action,
        summary="bounded upload_package executed inside gateway boundary",
        details=[
            f"package={package_name}",
            f"registry={registry}",
            f"secret_handle={session.secret_handle}",
        ],
    )


def _execute_via_tibet_gateway_proxy(
    record: SAMRecord,
    session: GatewaySession,
    gateway_base_url: str,
) -> GatewayExecutionResult:
    if not record.upstream_url:
        raise SAMGatewayError("sam-upstream-missing", "proxy adapter requires upstream_url")
    parsed = urlparse(record.upstream_url)
    if not parsed.hostname:
        raise SAMGatewayError("sam-upstream-invalid", "upstream_url must have a hostname")
    constraints = _constraint_map(record)
    expected_host = constraints.get("host")
    if expected_host and expected_host != parsed.hostname:
        raise SAMGatewayError(
            "sam-constraint-mismatch",
            f"constraint host expected {expected_host} but upstream host is {parsed.hostname}",
        )
    payload = {
        "agent_id": record.actor_id,
        "intent": record.intent,
        "target_url": record.upstream_url,
        "method": record.upstream_method or "POST",
        "payload": record.upstream_payload or {},
        "headers": {},
    }
    req = Request(
        gateway_base_url.rstrip("/") + "/proxy",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            response_text = resp.read().decode("utf-8", errors="replace")
            status_code = getattr(resp, "status", 200)
    except Exception as exc:
        raise SAMGatewayError("sam-gateway-proxy-failed", str(exc)) from exc
    return GatewayExecutionResult(
        action=record.target_action,
        summary="bounded proxy action executed through tibet-gateway",
        details=[
            f"gateway_base_url={gateway_base_url}",
            f"upstream_url={record.upstream_url}",
            f"upstream_status={status_code}",
            f"secret_handle={session.secret_handle}",
            f"gateway_response_bytes={len(response_text)}",
        ],
    )


def _execute_generic(record: SAMRecord, session: GatewaySession) -> GatewayExecutionResult:
    return GatewayExecutionResult(
        action=record.target_action,
        summary="bounded action executed inside gateway boundary",
        details=[
            f"intent={record.intent}",
            f"secret_handle={session.secret_handle}",
        ],
    )


def list_runtime_adapters() -> list[dict[str, str]]:
    return [
        {
            "intent": "upload_package",
            "target_action": "/upload/pypi",
            "adapter": "bounded-upload-package",
        },
        {
            "intent": "proxy_external_call",
            "target_action": "/proxy/http",
            "adapter": "tibet-gateway-http-proxy",
        },
        {
            "intent": "generic",
            "target_action": "*",
            "adapter": "generic-bounded-executor",
        },
    ]


def _execute_upstream_action(
    record: SAMRecord,
    session: GatewaySession,
    gateway_base_url: str | None = None,
) -> tuple[GatewayExecutionResult, str]:
    if record.intent == "upload_package" and record.target_action == "/upload/pypi":
        return _execute_upload_package(record, session), "bounded-upload-package"
    if record.target_action == "/proxy/http":
        if not gateway_base_url:
            raise SAMGatewayError("sam-gateway-url-required", "proxy/http adapter requires --gateway-base-url")
        return (
            _execute_via_tibet_gateway_proxy(record, session, gateway_base_url),
            "tibet-gateway-http-proxy",
        )
    return _execute_generic(record, session), "generic-bounded-executor"


def _destroy_ephemeral_session(session: GatewaySession) -> SAMGatewayEvent:
    return SAMGatewayEvent(
        "sam-session-destroyed",
        "pass",
        f"session_id={session.session_id}",
    )


def validate_and_execute_sam(
    record: SAMRecord,
    *,
    requested_action: str,
    request_actor: str,
    request_constraints: list[tuple[str, str]] | None = None,
    gateway_actor: str = "jis:humotica:tibet-gateway",
    gateway_base_url: str | None = None,
    keychain_record: dict | None = None,
) -> SAMGatewayResponse:
    events: list[SAMGatewayEvent] = []
    events.append(SAMGatewayEvent("sam-received", "pass", f"sam_id={record.sam_id}"))

    now = datetime.now(timezone.utc)
    if _parse_utc(record.valid_until) < now:
        raise SAMGatewayError("sam-expired", f"valid_until={record.valid_until}")
    events.append(SAMGatewayEvent("sam-validated", "pass", f"valid_until={record.valid_until}"))

    if record.actor_id != request_actor:
        raise SAMGatewayError(
            "sam-actor-mismatch",
            f"sam actor {record.actor_id} does not match request actor {request_actor}",
        )
    events.append(SAMGatewayEvent("sam-actor-match", "pass", f"actor_id={request_actor}"))

    if record.target_action != requested_action:
        raise SAMGatewayError(
            "sam-constraint-mismatch",
            f"target_action {record.target_action} does not match requested_action {requested_action}",
        )

    expected_constraints = _constraint_map(record)
    provided_constraints = dict(request_constraints or [])
    for key, expected in expected_constraints.items():
        actual = provided_constraints.get(key)
        if actual != expected:
            raise SAMGatewayError(
                "sam-constraint-mismatch",
                f"constraint {key} expected {expected} but got {actual!r}",
            )
    events.append(SAMGatewayEvent("sam-constraint-match", "pass", f"constraints={len(expected_constraints)}"))
    events.extend(_validate_policy_lane(record))

    if keychain_record is not None:
        for name, status, detail in validate_keychain_binding(
            keychain_record=keychain_record,
            secret_id=record.secret_id,
            actor_id=record.actor_id,
        ):
            if status == "fail":
                raise SAMGatewayError("sam-keychain-denied", f"{name}: {detail}")
            events.append(SAMGatewayEvent("sam-keychain-check", status, f"{name}={detail}"))

    session, opened_event = _break_seal_within_runtime(record, gateway_actor)
    events.append(opened_event)
    events.append(SAMGatewayEvent("sam-secret-proxied", "pass", session.secret_handle))
    execution, runtime_adapter = _execute_upstream_action(record, session, gateway_base_url=gateway_base_url)
    events.append(SAMGatewayEvent("sam-executed", "pass", f"executed_action={execution.action}"))
    events.extend(SAMGatewayEvent("sam-runtime-detail", "pass", detail) for detail in execution.details)
    events.append(_destroy_ephemeral_session(session))
    events.append(SAMGatewayEvent("sam-response-sealed", "pass", "sandbox response shape emitted"))

    return SAMGatewayResponse(
        sam_id=record.sam_id,
        ephemeral_id=record.ephemeral_id,
        requested_action=requested_action,
        executed_action=record.target_action,
        status="executed",
        gateway_actor=gateway_actor,
        executed_at=_utc_now(),
        result_summary=execution.summary,
        policy_verdict="allow",
        destroy_session_confirmed=True,
        policy_lane=record.policy_lane,
        receipt_required=record.receipt_required,
        runtime_adapter=runtime_adapter,
        events=events,
    )


def render_gateway_failure(
    exc: SAMGatewayError,
    *,
    record: SAMRecord | None = None,
    requested_action: str = "<denied>",
    sam_id: str | None = None,
    gateway_actor: str = "jis:humotica:tibet-gateway",
) -> SAMGatewayResponse:
    return SAMGatewayResponse(
        sam_id=sam_id or (record.sam_id if record else "<unknown>"),
        ephemeral_id=record.ephemeral_id if record else "<unknown>",
        requested_action=requested_action,
        executed_action=None,
        status="denied",
        gateway_actor=gateway_actor,
        executed_at=_utc_now(),
        result_summary=exc.detail,
        policy_verdict=exc.code,
        destroy_session_confirmed=True,
        policy_lane=record.policy_lane if record else None,
        receipt_required=record.receipt_required if record else True,
        runtime_adapter=None,
        events=[
            SAMGatewayEvent("sam-denied", "fail", f"{exc.code}: {exc.detail}"),
        ],
    )


def emit_gateway_receipt_bundle(
    response: SAMGatewayResponse,
    *,
    bundle_out: str,
    identity_dir: str,
    receiver_aint: str = "self.aint",
    receiver_pubkey: str = "0" * 64,
    surface_time: str | None = None,
    surface_context: str = "sam-receipt",
    surface_profile: str = "normal",
    surface_priority: str = "background",
) -> dict:
    payload = json.dumps(response.to_dict(), indent=2, sort_keys=True).encode("utf-8")
    result = emit_sealed_payload_bundle(
        payload_bytes=payload,
        block_name="sam-response.json",
        payload_type="sam_gateway_receipt",
        bundle_out=bundle_out,
        identity_dir=identity_dir,
        expected_actor_id=response.gateway_actor,
        result_id=response.sam_id,
        receiver_aint=receiver_aint,
        receiver_pubkey=receiver_pubkey,
        surface_time=surface_time,
        surface_context=surface_context,
        surface_profile=surface_profile,
        surface_priority=surface_priority,
    )
    result["sam_id"] = response.sam_id
    return result
