from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from uuid import uuid4

from .keychain_bridge import validate_keychain_binding
from .types import SAMConstraint, SAMRecord


def _utc_after(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def materialize_sam(
    *,
    intent: str,
    secret_id: str,
    target_action: str,
    actor_id: str,
    policy_lane: str | None = None,
    receipt_required: bool = True,
    supersedes_sam_id: str | None = None,
    upstream_url: str | None = None,
    upstream_method: str | None = None,
    upstream_payload: dict | None = None,
    keychain_record: dict | None = None,
    constraints: list[tuple[str, str]] | None = None,
    valid_for_seconds: int = 300,
) -> SAMRecord:
    notes = [
        "package authority capsule",
        "can now be emitted as a sealed .tza capsule",
        "intended to become an intent-bound one-shot authority capsule",
    ]
    if keychain_record is not None:
        for name, status, detail in validate_keychain_binding(
            keychain_record=keychain_record,
            secret_id=secret_id,
            actor_id=actor_id,
        ):
            if status == "fail":
                raise ValueError(f"{name}: {detail}")
        notes.append("keychain_binding=validated")
    return SAMRecord(
        sam_id=f"sam_{uuid4().hex[:12]}",
        intent=intent,
        secret_id=secret_id,
        target_action=target_action,
        actor_id=actor_id,
        valid_until=_utc_after(valid_for_seconds),
        ephemeral_id=f"eph_{uuid4().hex[:12]}",
        policy_lane=policy_lane,
        receipt_required=receipt_required,
        supersedes_sam_id=supersedes_sam_id,
        upstream_url=upstream_url,
        upstream_method=upstream_method,
        upstream_payload=dict(upstream_payload or {}),
        constraints=[
            SAMConstraint(key=key, value=value)
            for key, value in (constraints or [])
        ],
        notes=notes,
    )


def _load_identity(identity_dir: Path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    import json as _json

    priv_bytes = (identity_dir / "identity.priv").read_bytes()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    info = _json.loads((identity_dir / "identity.json").read_text())

    try:
        from tibet_drop.crypto import IdentityKey  # type: ignore
    except ImportError:
        local_src = "/srv/jtel-stack/sandbox/airdrop-cli/src"
        if local_src not in sys.path:
            sys.path.insert(0, local_src)
        from tibet_drop.crypto import IdentityKey  # type: ignore

    return IdentityKey(priv=priv, pub=priv.public_key()), info["aint"]


def emit_sealed_payload_bundle(
    *,
    payload_bytes: bytes,
    block_name: str,
    payload_type: str,
    bundle_out: str,
    identity_dir: str,
    expected_actor_id: str | None = None,
    result_id: str | None = None,
    receiver_aint: str = "self.aint",
    receiver_pubkey: str = "0" * 64,
    surface_time: str | None = None,
    surface_context: str = "sam",
    surface_profile: str = "normal",
    surface_priority: str = "normal",
) -> dict:
    try:
        from tibet_drop.bundle import pack_bundle  # type: ignore
    except ImportError:
        local_src = "/srv/jtel-stack/sandbox/airdrop-cli/src"
        if local_src not in sys.path:
            sys.path.insert(0, local_src)
        from tibet_drop.bundle import pack_bundle  # type: ignore
    import os
    import time

    out_path = Path(bundle_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    signer, sender_aint = _load_identity(Path(identity_dir))
    if expected_actor_id is not None and sender_aint != expected_actor_id:
        raise ValueError(
            f"identity actor mismatch: identity_dir is {sender_aint}, "
            f"but expected actor is {expected_actor_id}"
        )

    if surface_time is None:
        surface_time = time.strftime("%Y-%m-%d", time.gmtime())

    manifest = pack_bundle(
        output_path=out_path,
        blocks=[(block_name, payload_bytes)],
        sender_aint=sender_aint,
        sender_signer=signer,
        receiver_aint=receiver_aint,
        receiver_pubkey_hex=receiver_pubkey,
        payload_type=payload_type,
        tpid=os.urandom(16),
        surface_time_fragment=surface_time,
        surface_context=surface_context,
        surface_profile=surface_profile,
        surface_priority=surface_priority,
    )

    result = {
        "bundle_out": str(out_path.resolve()),
        "sender_aint": sender_aint,
        "receiver_aint": receiver_aint,
        "manifest": manifest,
    }
    if result_id is not None:
        result["result_id"] = result_id
    return result


def emit_sam_bundle(
    record: SAMRecord,
    *,
    bundle_out: str,
    identity_dir: str,
    receiver_aint: str = "self.aint",
    receiver_pubkey: str = "0" * 64,
    surface_time: str | None = None,
    surface_context: str = "sam",
    surface_profile: str = "normal",
    surface_priority: str = "normal",
) -> dict:
    content = json.dumps(record.to_dict(), indent=2, sort_keys=True).encode("utf-8")
    result = emit_sealed_payload_bundle(
        payload_bytes=content,
        block_name="sam.json",
        payload_type="sam_capsule",
        bundle_out=bundle_out,
        identity_dir=identity_dir,
        expected_actor_id=record.actor_id,
        result_id=record.sam_id,
        receiver_aint=receiver_aint,
        receiver_pubkey=receiver_pubkey,
        surface_time=surface_time,
        surface_context=surface_context,
        surface_profile=surface_profile,
        surface_priority=surface_priority,
    )
    result["sam_id"] = record.sam_id
    return result
