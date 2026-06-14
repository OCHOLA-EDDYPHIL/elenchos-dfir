from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from typing import Any

from elenchos import __version__
from elenchos.integrations.tool_adapter import (
    dispatch_tool,
    get_tool_definitions,
    sanitize_model_error,
)

JSONRPC_VERSION = "2.0"
SUPPORTED_PROTOCOL_VERSION = "2025-11-25"


def _response(request_id: object, result: object) -> dict[str, object]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _error(request_id: object, code: int, message: str) -> dict[str, object]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": sanitize_model_error(message)},
    }


def _tool_result(payload: dict[str, object], *, is_error: bool = False) -> dict[str, object]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2, sort_keys=True),
            }
        ],
        "structuredContent": payload,
        "isError": is_error,
    }


def _params_object(message: Mapping[str, object]) -> dict[str, Any]:
    params = message.get("params", {})
    if params is None:
        return {}
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    return dict(params)


def handle_message(message: Mapping[str, object]) -> dict[str, object] | None:
    request_id = message.get("id")
    method = message.get("method")
    if not isinstance(method, str):
        return _error(request_id, -32600, "method must be a string")

    if method == "notifications/initialized":
        return None
    if method == "initialize":
        params = _params_object(message)
        protocol_version = params.get("protocolVersion")
        if not isinstance(protocol_version, str):
            protocol_version = SUPPORTED_PROTOCOL_VERSION
        return _response(
            request_id,
            {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "elenchos-openclaw-adapter",
                    "version": __version__,
                    "description": "Bounded Elenchos deterministic forensic tool adapter.",
                },
            },
        )
    if method == "ping":
        return _response(request_id, {})
    if method == "tools/list":
        return _response(request_id, {"tools": get_tool_definitions()})
    if method == "tools/call":
        params = _params_object(message)
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name:
            return _error(request_id, -32602, "tools/call requires a tool name")
        if not isinstance(arguments, dict):
            return _error(request_id, -32602, "tools/call arguments must be an object")
        try:
            result = dispatch_tool(name, arguments)
        except Exception as exc:
            return _response(
                request_id,
                _tool_result(
                    {"status": "failed", "error": sanitize_model_error(exc)},
                    is_error=True,
                ),
            )
        is_error = result.get("status") == "failed" or result.get("validation_status") == "fail"
        return _response(request_id, _tool_result(result, is_error=is_error))
    return _error(request_id, -32601, f"unsupported method: {method}")


def serve() -> int:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("JSON-RPC message must be an object")
            response = handle_message(message)
        except json.JSONDecodeError as exc:
            response = _error(None, -32700, f"parse error: {exc.msg}")
        except Exception as exc:
            response = _error(None, -32603, str(exc))
        if response is None:
            continue
        print(json.dumps(response, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
