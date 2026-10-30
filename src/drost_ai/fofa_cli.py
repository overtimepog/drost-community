"""FOFA internet-wide asset search helpers for the Drost container."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import sys
from typing import Any, Sequence
from urllib.parse import quote

import requests

API_BASE = "https://fofa.info/api/v1"
DEFAULT_FIELDS = ("host", "ip", "port", "domain", "title", "server", "protocol")
DEFAULT_TIMEOUT = 30.0
MAX_PAGE_SIZE = 10_000
USER_AGENT = "drost-fofa/1.0 (+https://github.com/drost-ai/drost-community)"


class FofaError(RuntimeError):
    """Raised when FOFA cannot answer a request."""


def _api_key(key: str | None = None) -> str:
    value = (key or os.environ.get("FOFA_KEY", "")).strip()
    if not value:
        raise FofaError("missing FOFA API key; set FOFA_KEY or pass --key")
    return value


def _auth_params(key: str | None, email: str | None) -> dict[str, str]:
    params = {"key": _api_key(key)}
    resolved_email = (email or os.environ.get("FOFA_EMAIL", "")).strip()
    if resolved_email:
        params["email"] = resolved_email
    return params


def encode_query(query: str) -> str:
    """Return the base64 form FOFA expects for a query string."""
    cleaned = query.strip()
    if not cleaned:
        raise FofaError("query must not be empty")
    return base64.b64encode(cleaned.encode("utf-8")).decode("ascii")


def parse_fields(raw: str | None) -> list[str]:
    fields = [item.strip() for item in (raw or "").split(",") if item.strip()]
    return fields or list(DEFAULT_FIELDS)


def _fetch_json(endpoint: str, params: dict[str, str], timeout: float) -> dict[str, Any]:
    if timeout <= 0:
        raise FofaError("timeout must be positive")
    url = f"{API_BASE}/{endpoint.lstrip('/')}"
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        detail = str(exc)
        api_key = params.get("key")
        if api_key:
            detail = detail.replace(api_key, "***")
        raise FofaError(f"FOFA request failed: {detail}") from exc
    if response.status_code != 200:
        raise FofaError(f"FOFA returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except ValueError as exc:
        raise FofaError("FOFA returned a non-JSON response") from exc
    if not isinstance(payload, dict):
        raise FofaError("FOFA returned an unexpected response")
    if payload.get("error"):
        raise FofaError(str(payload.get("errmsg") or "unknown FOFA error"))
    return payload


def _records(fields: Sequence[str], rows: Sequence[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            records.append(row)
            continue
        if isinstance(row, (list, tuple)):
            record = {
                field: row[index] if index < len(row) else None
                for index, field in enumerate(fields)
            }
            if len(row) > len(fields):
                record["_extra"] = list(row[len(fields) :])
            records.append(record)
            continue
        records.append({"value": row})
    return records


def search(
    query: str,
    *,
    fields: Sequence[str] | None = None,
    page: int = 1,
    size: int = 100,
    full: bool = False,
    key: str | None = None,
    email: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Run a FOFA ``search/all`` query and return records keyed by field name."""
    field_list = list(fields) if fields else list(DEFAULT_FIELDS)
    if page < 1:
        raise FofaError("page must be at least 1")
    if not 1 <= size <= MAX_PAGE_SIZE:
        raise FofaError(f"size must be between 1 and {MAX_PAGE_SIZE}")
    params = _auth_params(key, email)
    params.update(
        {
            "qbase64": encode_query(query),
            "fields": ",".join(field_list),
            "page": str(page),
            "size": str(size),
        }
    )
    if full:
        params["full"] = "true"
    payload = _fetch_json("search/all", params, timeout)
    rows = payload.get("results") or []
    if not isinstance(rows, list):
        raise FofaError("FOFA returned an unexpected results payload")
    return {
        "query": query.strip(),
        "fields": field_list,
        "page": page,
        "requested": size,
        "total": payload.get("size"),
        "returned": len(rows),
        "results": _records(field_list, rows),
    }


def account_info(
    *,
    key: str | None = None,
    email: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Return FOFA account status and remaining query allowance."""
    payload = _fetch_json("info/my", _auth_params(key, email), timeout)
    return {name: value for name, value in payload.items() if name not in {"error", "errmsg"}}


def host_info(
    host: str,
    *,
    detail: bool = True,
    key: str | None = None,
    email: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Return FOFA's aggregated record for one host."""
    cleaned = host.strip()
    if not cleaned:
        raise FofaError("host must not be empty")
    params = _auth_params(key, email)
    params["detail"] = "true" if detail else "false"
    payload = _fetch_json(f"host/{quote(cleaned, safe='')}", params, timeout)
    return {name: value for name, value in payload.items() if name not in {"error", "errmsg"}}


def search_stats(
    query: str,
    *,
    field: str = "protocol",
    key: str | None = None,
    email: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Return FOFA aggregate statistics for a query."""
    cleaned_field = field.strip()
    if not cleaned_field:
        raise FofaError("field must not be empty")
    params = _auth_params(key, email)
    params.update({"qbase64": encode_query(query), "fields": cleaned_field})
    payload = _fetch_json("search/stats", params, timeout)
    return {
        "query": query.strip(),
        "field": cleaned_field,
        "distinct": payload.get("distinct"),
        "aggs": payload.get("aggs"),
    }


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False)
    return text.replace("\t", " ").replace("\r", " ").replace("\n", " ")


def _format_table(data: dict[str, Any]) -> str:
    if "results" in data and "fields" in data:
        fields = list(data["fields"])
        lines = ["\t".join(fields)]
        for row in data["results"]:
            lines.append("\t".join(_cell(row.get(field)) for field in fields))
        return "\n".join(lines)
    return "\n".join(f"{key}\t{_cell(value)}" for key, value in data.items())


def _format(data: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False)
    if fmt == "jsonl":
        if "results" in data:
            return "\n".join(
                json.dumps(row, ensure_ascii=False) for row in data["results"]
            )
        return json.dumps(data, ensure_ascii=False)
    return _format_table(data)


def _emit(data: dict[str, Any], fmt: str, output: str | None) -> None:
    text = _format(data, fmt) + "\n"
    if output:
        path = Path(output).expanduser()
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise FofaError(f"cannot write {path}: {exc}") from exc
        return
    sys.stdout.write(text)


def _common_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--key", help="FOFA API key (default: FOFA_KEY)")
    common.add_argument(
        "--email",
        help="FOFA account email (default: FOFA_EMAIL; usually unnecessary with key-only auth)",
    )
    common.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    common.add_argument("--format", choices=("json", "jsonl", "table"), default="json")
    common.add_argument("-o", "--output", help="write results to this file instead of stdout")
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drost-fofa",
        description="Search the FOFA internet-wide asset index from the Drost container.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    common = _common_parser()

    sub = subparsers.add_parser(
        "search", parents=[common], help="run a FOFA search query"
    )
    sub.add_argument("query", help='FOFA query syntax, for example domain="example.com"')
    sub.add_argument("--fields", default=",".join(DEFAULT_FIELDS))
    sub.add_argument("--page", type=int, default=1)
    sub.add_argument("--size", type=int, default=100)
    sub.add_argument("--full", action="store_true", help="request full field data")
    sub.set_defaults(func=cmd_search)

    sub = subparsers.add_parser(
        "host", parents=[common], help="retrieve FOFA's record for one host"
    )
    sub.add_argument("host", help="IP address or domain")
    sub.add_argument("--no-detail", action="store_true", help="omit detailed service data")
    sub.set_defaults(func=cmd_host)

    sub = subparsers.add_parser(
        "stats", parents=[common], help="aggregate a query by one field"
    )
    sub.add_argument("query", help="FOFA query syntax")
    sub.add_argument("--field", default="protocol")
    sub.set_defaults(func=cmd_stats)

    sub = subparsers.add_parser(
        "info", parents=[common], help="show account status and remaining quota"
    )
    sub.set_defaults(func=cmd_info)

    return parser


def cmd_search(args: argparse.Namespace) -> int:
    data = search(
        args.query,
        fields=parse_fields(args.fields),
        page=args.page,
        size=args.size,
        full=args.full,
        key=args.key,
        email=args.email,
        timeout=args.timeout,
    )
    _emit(data, args.format, args.output)
    return 0


def cmd_host(args: argparse.Namespace) -> int:
    data = host_info(
        args.host,
        detail=not args.no_detail,
        key=args.key,
        email=args.email,
        timeout=args.timeout,
    )
    _emit(data, args.format, args.output)
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    data = search_stats(
        args.query,
        field=args.field,
        key=args.key,
        email=args.email,
        timeout=args.timeout,
    )
    _emit(data, args.format, args.output)
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    data = account_info(key=args.key, email=args.email, timeout=args.timeout)
    _emit(data, args.format, args.output)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except FofaError as exc:
        print(f"drost-fofa: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return int(result) if result is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
