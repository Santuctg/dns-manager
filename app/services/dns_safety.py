from __future__ import annotations

import argparse
import ipaddress
import subprocess
from pathlib import Path
from typing import Any

from app.config import get_settings

BASE_CONFIG_PATH = Path("/etc/dnsmasq.d/00-dns-manager-base.conf")
SS_PATH = "/usr/bin/ss"


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None


def _is_valid_dns_bind_ip(value: str) -> bool:
    ip = _parse_ip(value)
    if ip is None:
        return False
    return bool(
        not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
    )


def _active_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def validate_base_config(text: str, expected_ip: str) -> dict[str, Any]:
    issues: list[str] = []
    expected_ip = (expected_ip or "").strip()
    expected_obj = _parse_ip(expected_ip)
    if not _is_valid_dns_bind_ip(expected_ip):
        issues.append("expected DNS listen address must be a valid unicast IP")

    lines = _active_lines(text)
    listen_values = [line.split("=", 1)[1].strip() for line in lines if line.startswith("listen-address=")]
    if not listen_values:
        issues.append("listen-address is required")
    else:
        for value in listen_values:
            ip = _parse_ip(value)
            if ip is None or ip.is_unspecified or value in {"0.0.0.0", "::", "*"}:
                issues.append(f"unsafe listen-address: {value}")
            elif expected_obj is None or ip != expected_obj:
                issues.append(f"unexpected listen-address: {value}")
        if len(listen_values) != 1:
            issues.append("exactly one listen-address is required")

    if "bind-interfaces" not in lines:
        issues.append("bind-interfaces is required")
    if "no-resolv" not in lines:
        issues.append("no-resolv is required")

    servers = [line.split("=", 1)[1].strip() for line in lines if line.startswith("server=")]
    if not servers or any(not value for value in servers):
        issues.append("at least one explicit server= upstream is required")
    for value in servers:
        # Support the common dnsmasq server=<ip>[#port] form. Domain-specific
        # routing remains intentionally unsupported in the safety base file.
        host = value.split("#", 1)[0].strip("[]")
        ip = _parse_ip(host)
        if ip is None:
            issues.append(f"server= upstream must be an IP address: {value}")
            continue
        if ip.is_unspecified or (expected_obj is not None and ip == expected_obj):
            issues.append(f"unsafe server= upstream: {value}")

    forbidden_prefixes = ("interface=", "except-interface=", "bind-dynamic")
    for line in lines:
        if line.startswith(forbidden_prefixes):
            issues.append(f"ambiguous bind directive is not allowed: {line}")

    return {"safe": not issues, "issues": issues, "listen_addresses": listen_values, "upstreams": servers}



def reconcile_base_config(text: str, expected_ip: str) -> str:
    expected_ip = (expected_ip or "").strip()
    if not _is_valid_dns_bind_ip(expected_ip):
        raise ValueError("expected DNS listen address must be a valid unicast IP")

    active = _active_lines(text)
    listen_values = [line.split("=", 1)[1].strip() for line in active if line.startswith("listen-address=")]
    if len(listen_values) != 1:
        raise ValueError("exactly one listen-address is required before reconciliation")
    current = listen_values[0]
    current_ip = _parse_ip(current)
    if current_ip is None or current_ip.is_unspecified or current in {"0.0.0.0", "::", "*"}:
        raise ValueError(f"unsafe listen-address cannot be reconciled automatically: {current}")

    output: list[str] = []
    replaced = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        if stripped.startswith("listen-address=") and not stripped.startswith("#"):
            ending = "\n" if raw.endswith("\n") else ""
            output.append(f"listen-address={expected_ip}{ending}")
            replaced = True
        else:
            output.append(raw)
    if not replaced:
        raise ValueError("listen-address is required before reconciliation")
    return "".join(output)

def _binding_host(token: str) -> str | None:
    token = token.strip()
    if not token or ":53" not in token:
        return None
    if token.startswith("[") and "]:53" in token:
        host = token[1:].split("]", 1)[0]
    else:
        host = token.rsplit(":53", 1)[0]
    if "%" in host:
        host = host.split("%", 1)[0]
    return host


def validate_runtime_bindings(ss_output: str, expected_ip: str) -> dict[str, Any]:
    issues: list[str] = []
    bindings: set[str] = set()
    expected = _parse_ip(expected_ip)

    for line in ss_output.splitlines():
        for token in line.split():
            host = _binding_host(token)
            if host is None:
                continue
            if host in {"*", "0.0.0.0", "::"}:
                bindings.add(host)
                issues.append(f"wildcard DNS bind detected: {host}:53")
                break
            ip = _parse_ip(host)
            if ip is None:
                continue
            normalized = str(ip)
            bindings.add(normalized)
            if ip.is_loopback:
                break
            if expected is None or ip != expected:
                issues.append(f"unexpected non-loopback DNS bind detected: {normalized}:53")
            break

    expected_normalized = str(expected) if expected is not None else expected_ip
    if expected_normalized not in bindings:
        issues.append(f"expected DNS address is not bound on port 53: {expected_ip}")

    return {"safe": not issues, "issues": issues, "bindings": sorted(bindings)}


def _read_runtime_bindings() -> str:
    try:
        completed = subprocess.run(
            [SS_PATH, "-H", "-lnut", "sport", "=", ":53"],
            check=True,
            text=True,
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"unable to inspect DNS socket bindings: {exc}") from exc
    return completed.stdout


def get_dns_safety_status(
    *,
    expected_ip: str | None = None,
    config_path: Path = BASE_CONFIG_PATH,
    ss_output: str | None = None,
) -> dict[str, Any]:
    expected_ip = expected_ip or get_settings().internal_proxy_ip
    if not expected_ip:
        return {
            "safe": False,
            "config_safe": False,
            "runtime_safe": False,
            "expected_ip": None,
            "bindings": [],
            "issues": ["DNS_MANAGER_INTERNAL_PROXY_IP is not configured"],
        }

    try:
        config_text = config_path.read_text()
        config = validate_base_config(config_text, expected_ip)
    except OSError as exc:
        config = {"safe": False, "issues": [f"unable to read dnsmasq base config: {exc}"]}

    try:
        runtime_text = _read_runtime_bindings() if ss_output is None else ss_output
        runtime = validate_runtime_bindings(runtime_text, expected_ip)
    except RuntimeError as exc:
        runtime = {"safe": False, "issues": [str(exc)], "bindings": []}

    issues = list(config.get("issues", [])) + list(runtime.get("issues", []))
    return {
        "safe": bool(config.get("safe")) and bool(runtime.get("safe")),
        "config_safe": bool(config.get("safe")),
        "runtime_safe": bool(runtime.get("safe")),
        "expected_ip": expected_ip,
        "bindings": runtime.get("bindings", []),
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate DNS Manager dnsmasq network safety")
    parser.add_argument("--check-base", type=Path, metavar="PATH")
    parser.add_argument("--reconcile-base", type=Path, metavar="PATH")
    parser.add_argument("--expected-ip", required=True)
    args = parser.parse_args()
    if bool(args.check_base) == bool(args.reconcile_base):
        parser.error("exactly one of --check-base or --reconcile-base is required")

    path = args.reconcile_base or args.check_base
    try:
        text = path.read_text()
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}")
        return 1

    if args.reconcile_base:
        try:
            text = reconcile_base_config(text, args.expected_ip)
        except ValueError as exc:
            print(f"ERROR: {exc}")
            return 1
        try:
            path.write_text(text)
        except OSError as exc:
            print(f"ERROR: cannot update {path}: {exc}")
            return 1

    result = validate_base_config(text, args.expected_ip)
    if not result["safe"]:
        for issue in result["issues"]:
            print(f"ERROR: {issue}")
        return 1
    print(f"DNS safety base config OK: {path} -> {args.expected_ip}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
