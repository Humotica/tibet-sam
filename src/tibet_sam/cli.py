from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .gateway import (
    emit_gateway_receipt_bundle,
    list_runtime_adapters,
    load_sam,
    render_gateway_failure,
    validate_and_execute_sam,
)
from .inspect import inspect_sam_file, verify_sam_file
from .materialize import emit_sam_bundle, materialize_sam


def _parse_constraint(item: str) -> tuple[str, str]:
    if "=" not in item:
        raise argparse.ArgumentTypeError("constraint must be key=value")
    key, value = item.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not key or not value:
        raise argparse.ArgumentTypeError("constraint must be key=value")
    return key, value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tibet-sam")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info", help="Show the SAM family framing")
    sub.add_parser("types", help="Show core SAM fields")
    p_runtime = sub.add_parser("runtime", help="Show local gateway runtime adapters")
    p_runtime.add_argument("--json", action="store_true")
    p_inspect = sub.add_parser("inspect", help="Inspect a SAM JSON or sealed .tza capsule")
    p_inspect.add_argument("sam_file")
    p_inspect.add_argument("--json", action="store_true")
    p_verify = sub.add_parser("verify", help="Verify a SAM JSON or sealed .tza capsule")
    p_verify.add_argument("sam_file")
    p_verify.add_argument("--json", action="store_true")

    p_materialize = sub.add_parser("materialize", help="Build a sandbox SAM payload")
    p_materialize.add_argument("--intent", required=True)
    p_materialize.add_argument("--secret-id", required=True)
    p_materialize.add_argument("--target-action", required=True)
    p_materialize.add_argument("--actor-id", default="agent.ai")
    p_materialize.add_argument("--constraint", action="append", type=_parse_constraint, default=[])
    p_materialize.add_argument("--valid-for-seconds", type=int, default=300)
    p_materialize.add_argument("--emit-bundle")
    p_materialize.add_argument("--identity-dir")
    p_materialize.add_argument("--receiver-aint", default="self.aint")
    p_materialize.add_argument("--receiver-pubkey", default="0" * 64)
    p_materialize.add_argument("--surface-time")
    p_materialize.add_argument("--surface-context", default="sam")
    p_materialize.add_argument("--surface-profile", default="normal")
    p_materialize.add_argument("--surface-priority", default="normal")
    p_materialize.add_argument("--emit-sidecar-debug", action="store_true")
    p_materialize.add_argument("--json", action="store_true")

    p_execute = sub.add_parser("execute", help="Mock gateway-side execution using a SAM payload")
    p_execute.add_argument("--sam-file", required=True)
    p_execute.add_argument("--requested-action", required=True)
    p_execute.add_argument("--request-actor", required=True)
    p_execute.add_argument("--constraint", action="append", type=_parse_constraint, default=[])
    p_execute.add_argument("--gateway-actor", default="jis:humotica:tibet-gateway")
    p_execute.add_argument("--gateway-identity-dir")
    p_execute.add_argument("--response-bundle")
    p_execute.add_argument("--receiver-aint", default="self.aint")
    p_execute.add_argument("--receiver-pubkey", default="0" * 64)
    p_execute.add_argument("--surface-time")
    p_execute.add_argument("--surface-context", default="sam-receipt")
    p_execute.add_argument("--surface-profile", default="normal")
    p_execute.add_argument("--surface-priority", default="background")
    p_execute.add_argument("--json", action="store_true")

    return parser


def _cmd_info() -> int:
    print("tibet-sam")
    print("  WHY primitive in the four-W family")
    print("  authorizes one bounded act without releasing the underlying secret")
    return 0


def _cmd_types() -> int:
    print("SAM fields:")
    print("  - sam_id")
    print("  - intent")
    print("  - secret_id")
    print("  - target_action")
    print("  - actor_id")
    print("  - valid_until")
    print("  - ephemeral_id")
    print("  - constraints[]")
    return 0


def _cmd_runtime(args: argparse.Namespace) -> int:
    payload = {"runtime_adapters": list_runtime_adapters()}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print("Runtime adapters:")
    for item in payload["runtime_adapters"]:
        print(f"  - {item['adapter']}: intent={item['intent']} target_action={item['target_action']}")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    payload = inspect_sam_file(args.sam_file)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    print(f"File:        {payload['file']}")
    print(f"Source:      {payload['source_kind']}")
    print(f"SAM ID:      {payload['sam']['sam_id']}")
    print(f"Intent:      {payload['sam']['intent']}")
    print(f"Actor:       {payload['sam']['actor_id']}")
    print(f"Action:      {payload['sam']['target_action']}")
    print(f"Valid Until: {payload['sam']['valid_until']}")
    if payload["source_kind"] == "sealed-bundle":
        print(f"Manifest:    {str(payload.get('manifest_verify_valid')).lower()}")
        print(f"Payload:     {payload.get('manifest', {}).get('payload_type', '<unknown>')}")
        print(f"Blocks:      {', '.join(payload.get('block_names', [])) or '<none>'}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    payload = verify_sam_file(args.sam_file)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"File:     {payload['file']}")
        print(f"Verdict:  {payload['verdict']}")
        for check in payload["checks"]:
            marker = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}[check["status"]]
            print(f"  {marker:<4} {check['check']}: {check['detail']}")
    return 0 if payload["verdict"] != "fail" else 1


def _cmd_materialize(args: argparse.Namespace) -> int:
    sam = materialize_sam(
        intent=args.intent,
        secret_id=args.secret_id,
        target_action=args.target_action,
        actor_id=args.actor_id,
        constraints=args.constraint,
        valid_for_seconds=args.valid_for_seconds,
    )
    payload = sam.to_dict()
    if args.emit_bundle:
        if not args.identity_dir:
            raise SystemExit("ERROR: --identity-dir is required with --emit-bundle")
        bundle_result = emit_sam_bundle(
            sam,
            bundle_out=args.emit_bundle,
            identity_dir=args.identity_dir,
            receiver_aint=args.receiver_aint,
            receiver_pubkey=args.receiver_pubkey,
            surface_time=args.surface_time,
            surface_context=args.surface_context,
            surface_profile=args.surface_profile,
            surface_priority=args.surface_priority,
        )
        payload = {
            "sam": payload,
            "emitted_bundle": bundle_result,
            "notes": [
                "gateway should prefer the sealed .tza bundle as primary input",
            ],
        }
        if args.emit_sidecar_debug:
            sidecar = Path(args.emit_bundle).with_suffix(".sam.json")
            sidecar.write_text(json.dumps(sam.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
            payload["sidecar_json"] = str(sidecar)
            payload["notes"].append(
                "sidecar_json exists only for sandbox inspection and debug flows"
            )
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, indent=2))
    return 0


def _cmd_execute(args: argparse.Namespace) -> int:
    record = load_sam(args.sam_file)
    try:
        response = validate_and_execute_sam(
            record,
            requested_action=args.requested_action,
            request_actor=args.request_actor,
            request_constraints=args.constraint,
            gateway_actor=args.gateway_actor,
        )
        payload = {"response": response.to_dict()}
        if args.response_bundle:
            if not args.gateway_identity_dir:
                raise SystemExit("ERROR: --gateway-identity-dir is required with --response-bundle")
            payload["emitted_bundle"] = emit_gateway_receipt_bundle(
                response,
                bundle_out=args.response_bundle,
                identity_dir=args.gateway_identity_dir,
                receiver_aint=args.receiver_aint,
                receiver_pubkey=args.receiver_pubkey,
                surface_time=args.surface_time,
                surface_context=args.surface_context,
                surface_profile=args.surface_profile,
                surface_priority=args.surface_priority,
            )
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, indent=2))
        return 0
    except Exception as exc:
        if hasattr(exc, "code"):
            response = render_gateway_failure(exc, sam_id=record.sam_id, gateway_actor=args.gateway_actor)
        else:
            raise
        payload = {"response": response.to_dict()}
        if args.response_bundle and args.gateway_identity_dir:
            payload["emitted_bundle"] = emit_gateway_receipt_bundle(
                response,
                bundle_out=args.response_bundle,
                identity_dir=args.gateway_identity_dir,
                receiver_aint=args.receiver_aint,
                receiver_pubkey=args.receiver_pubkey,
                surface_time=args.surface_time,
                surface_context=args.surface_context,
                surface_profile=args.surface_profile,
                surface_priority=args.surface_priority,
            )
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else json.dumps(payload, indent=2))
        return 1


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    if args.command == "info":
        raise SystemExit(_cmd_info())
    if args.command == "types":
        raise SystemExit(_cmd_types())
    if args.command == "runtime":
        raise SystemExit(_cmd_runtime(args))
    if args.command == "inspect":
        raise SystemExit(_cmd_inspect(args))
    if args.command == "verify":
        raise SystemExit(_cmd_verify(args))
    if args.command == "materialize":
        raise SystemExit(_cmd_materialize(args))
    if args.command == "execute":
        raise SystemExit(_cmd_execute(args))
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
