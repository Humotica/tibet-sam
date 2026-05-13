from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import tempfile

from .gateway import load_sam


def _load_tibet_drop_bundle():
    from tibet_drop.bundle import inspect_bundle, unpack_bundle, verify_bundle  # type: ignore

    return inspect_bundle, unpack_bundle, verify_bundle


def _block_names(manifest: dict) -> list[str]:
    blocks = manifest.get("blocks", [])
    if not isinstance(blocks, list):
        return []
    names: list[str] = []
    for block in blocks:
        if isinstance(block, dict) and block.get("name"):
            names.append(str(block["name"]))
    return names


def inspect_sam_file(path: str) -> dict:
    source = Path(path)
    record = load_sam(path)
    payload = {
        "file": str(source.resolve()),
        "source_kind": "sealed-bundle" if source.suffix == ".tza" else "json",
        "sam": record.to_dict(),
    }
    if source.suffix != ".tza":
        return payload

    inspect_bundle, unpack_bundle, verify_bundle = _load_tibet_drop_bundle()
    manifest = inspect_bundle(source)
    valid, verified_manifest, errors = verify_bundle(source)
    if isinstance(verified_manifest, dict):
        manifest = verified_manifest
    payload["manifest"] = manifest
    payload["manifest_verify_valid"] = bool(valid)
    payload["verify_errors"] = list(errors)
    payload["block_names"] = _block_names(manifest if isinstance(manifest, dict) else {})

    with tempfile.TemporaryDirectory(prefix="tibet-sam-inspect-") as tmpdir:
        unpack_bundle(source, Path(tmpdir))
        payload["unpacked_files"] = sorted(
            p.name for p in Path(tmpdir).iterdir() if p.is_file()
        )
    return payload


def verify_sam_file(path: str) -> dict:
    inspected = inspect_sam_file(path)
    checks: list[dict[str, str]] = []
    source_kind = inspected["source_kind"]
    sam = inspected["sam"]

    required_fields = (
        "sam_id",
        "intent",
        "secret_id",
        "target_action",
        "actor_id",
        "valid_until",
        "ephemeral_id",
    )
    for field in required_fields:
        value = sam.get(field)
        checks.append(
            {
                "check": f"required:{field}",
                "status": "pass" if value else "fail",
                "detail": str(value) if value else "missing",
            }
        )

    try:
        valid_until = datetime.strptime(sam["valid_until"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        checks.append(
            {
                "check": "sam:not-expired",
                "status": "pass" if valid_until >= datetime.now(timezone.utc) else "fail",
                "detail": sam["valid_until"],
            }
        )
    except Exception:
        checks.append(
            {
                "check": "sam:not-expired",
                "status": "fail",
                "detail": "invalid valid_until format",
            }
        )

    if source_kind == "sealed-bundle":
        manifest = inspected.get("manifest", {})
        block_names = inspected.get("block_names", [])
        checks.append(
            {
                "check": "bundle:manifest-verify",
                "status": "pass" if inspected.get("manifest_verify_valid") else "fail",
                "detail": str(inspected.get("manifest_verify_valid")).lower(),
            }
        )
        checks.append(
            {
                "check": "bundle:payload-type",
                "status": "pass" if manifest.get("payload_type") == "sam_capsule" else "fail",
                "detail": str(manifest.get("payload_type")),
            }
        )
        checks.append(
            {
                "check": "bundle:sender-actor-match",
                "status": "pass" if manifest.get("sender_aint") == sam.get("actor_id") else "fail",
                "detail": f"{manifest.get('sender_aint')} vs {sam.get('actor_id')}",
            }
        )
        checks.append(
            {
                "check": "bundle:sam-json-block",
                "status": "pass" if "sam.json" in block_names else "fail",
                "detail": ",".join(block_names) if block_names else "<none>",
            }
        )
    else:
        checks.append(
            {
                "check": "source:sealed-bundle",
                "status": "warn",
                "detail": "JSON source is useful for debug but not sealed",
            }
        )

    verdict = "pass"
    if any(check["status"] == "fail" for check in checks):
        verdict = "fail"
    elif any(check["status"] == "warn" for check in checks):
        verdict = "warn"

    return {
        "file": inspected["file"],
        "source_kind": source_kind,
        "sam_id": sam.get("sam_id"),
        "verdict": verdict,
        "checks": checks,
        "sam": sam,
    }
