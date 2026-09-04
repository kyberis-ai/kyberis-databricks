from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError

from .config import DEFAULT_API_PREFIX, KyberisClientConfig
from .tool_schemas import ToolSpec


class KyberisClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class RequestResult:
    status_code: int
    body: dict[str, Any] | list[Any] | str | None


class KyberisClient:
    def __init__(self, config: KyberisClientConfig):
        self._config = config

    def _endpoint(self, endpoint: str) -> str:
        value = str(endpoint or "").strip()
        if value == DEFAULT_API_PREFIX:
            return self._config.api_prefix or "/"
        if value.startswith(f"{DEFAULT_API_PREFIX}/"):
            return f"{self._config.api_prefix}{value[len(DEFAULT_API_PREFIX):]}"
        return value

    def call_tool(self, spec: ToolSpec, args: dict[str, Any], *, auth_header: str) -> RequestResult:
        if spec.method == "POST":
            return self._post(spec.endpoint, args, auth_header=auth_header)
        if spec.method == "GET":
            return self._get(spec, args, auth_header=auth_header)
        raise KyberisClientError(f"Unsupported HTTP method: {spec.method}")

    def request_json(
        self,
        *,
        endpoint: str,
        method: str,
        payload: dict[str, Any] | None,
        auth_header: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> RequestResult:
        http_method = str(method or "").strip().upper()
        if http_method not in {"GET", "POST"}:
            raise KyberisClientError(f"Unsupported HTTP method: {method}")
        url = f"{self._config.base_url}{self._endpoint(endpoint)}"
        headers = {"Accept": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        if isinstance(extra_headers, dict):
            for key, value in extra_headers.items():
                k = str(key or "").strip()
                v = str(value or "").strip()
                if not k or not v:
                    continue
                headers[k] = v
        data: bytes | None = None
        if http_method == "POST":
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
        return self._request_with_retries(url=url, method=http_method, headers=headers, data=data)

    def _post(self, endpoint: str, payload: dict[str, Any], *, auth_header: str) -> RequestResult:
        url = f"{self._config.base_url}{self._endpoint(endpoint)}"
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return self._request_with_retries(url=url, method="POST", headers=headers, data=data)

    def _get(self, spec: ToolSpec, args: dict[str, Any], *, auth_header: str) -> RequestResult:
        path = spec.endpoint
        params: dict[str, str] = {}

        if "{canonical_id}" in path:
            canonical_id = str(args.get("canonical_id") or "").strip()
            if not canonical_id:
                raise KyberisClientError("canonical_id is required")
            path = path.replace("{canonical_id}", parse.quote(canonical_id, safe=""))
            params["include_aliases"] = str(bool(args.get("include_aliases", True))).lower()
            params["include_metadata"] = str(bool(args.get("include_metadata", True))).lower()
        elif "{evidence_id}" in path:
            evidence_id = str(args.get("evidence_id") or "").strip()
            if not evidence_id:
                raise KyberisClientError("evidence_id is required")
            path = path.replace("{evidence_id}", parse.quote(evidence_id, safe=""))
        else:
            raise KyberisClientError("Unsupported GET endpoint template")

        query = parse.urlencode(params)
        suffix = f"{path}?{query}" if query else path
        url = f"{self._config.base_url}{self._endpoint(suffix)}"

        headers = {
            "Authorization": auth_header,
            "Accept": "application/json",
        }
        agent_context = args.get("agent_context") if isinstance(args.get("agent_context"), dict) else {}
        header_map = {
            "objective": "X-Agent-Objective",
            "requested_outcome": "X-Agent-Requested-Outcome",
            "workflow_stage": "X-Agent-Workflow-Stage",
            "run_id": "X-Agent-Run-ID",
            "step_id": "X-Agent-Step-ID",
        }
        for field, header in header_map.items():
            value = str(agent_context.get(field) or "").strip()
            if value:
                headers[header] = value

        return self._request_with_retries(url=url, method="GET", headers=headers, data=None)

    def _request_with_retries(self, *, url: str, method: str, headers: dict[str, str], data: bytes | None) -> RequestResult:
        last_error: Exception | None = None

        for attempt in range(self._config.max_retries + 1):
            req = request.Request(url=url, data=data, headers=headers, method=method)
            try:
                with request.urlopen(req, timeout=self._config.timeout_seconds) as response:
                    raw = response.read().decode("utf-8")
                    return RequestResult(status_code=int(response.status), body=_try_parse_json(raw))
            except HTTPError as exc:
                raw = exc.read().decode("utf-8") if exc.fp else ""
                retryable = int(exc.code) in {429, 500, 502, 503, 504}
                if retryable and attempt < self._config.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                return RequestResult(status_code=int(exc.code), body=_try_parse_json(raw))
            except URLError as exc:
                last_error = exc
                if attempt < self._config.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                break

        raise KyberisClientError(f"Failed to call Kyberis API: {last_error}")


def _try_parse_json(raw: str) -> dict[str, Any] | list[Any] | str | None:
    text = str(raw or "")
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text
