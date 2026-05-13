from __future__ import annotations

import json
from pathlib import Path


def load_keychain_record(path: str) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("keychain record must be a JSON object")
    return payload


def validate_keychain_binding(
    *,
    keychain_record: dict,
    secret_id: str,
    actor_id: str,
) -> list[tuple[str, str, str]]:
    checks: list[tuple[str, str, str]] = []

    checks.append(
        (
            "keychain:secret-id-match",
            "pass" if keychain_record.get("secret_id") == secret_id else "fail",
            f"{keychain_record.get('secret_id')} vs {secret_id}",
        )
    )

    exposure_state = str(keychain_record.get("exposure_state", "sealed"))
    bad_exposure = {"chat-disclosed", "git-leaked", "log-leaked"}
    checks.append(
        (
            "keychain:exposure-state",
            "fail" if exposure_state in bad_exposure else "pass",
            exposure_state,
        )
    )

    rotation_required = bool(keychain_record.get("rotation_required", False))
    checks.append(
        (
            "keychain:rotation-required",
            "fail" if rotation_required else "pass",
            str(rotation_required).lower(),
        )
    )

    active_operator = keychain_record.get("active_operator_id")
    if active_operator:
        checks.append(
            (
                "keychain:active-operator-match",
                "pass" if active_operator == actor_id else "fail",
                f"{active_operator} vs {actor_id}",
            )
        )

    return checks
