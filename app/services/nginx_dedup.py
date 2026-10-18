from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path
from typing import Iterable

_SERVER_NAME_RE = re.compile(r"\bserver_name\s+([^;\s]+)\s*;")
_HTTP_LISTEN_RE = re.compile(r"\blisten\s+80(?:\s|;)")
_REDIRECT_RE = re.compile(r"\breturn\s+30[1278]\s+https://")


def _normalize_domains(domains: Iterable[str]) -> set[str]:
    return {str(domain).strip().lower().rstrip(".") for domain in domains if str(domain).strip()}


def _top_level_server_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    lines = text.splitlines(keepends=True)
    offset = 0
    in_server = False
    start = 0
    depth = 0
    block: list[str] = []

    for line in lines:
        stripped = line.lstrip()
        if not in_server and re.match(r"server\s*\{", stripped):
            in_server = True
            start = offset
            depth = 0
            block = []
        if in_server:
            block.append(line)
            # Generated DNS Manager configs do not contain braces in strings;
            # counting braces is sufficient and preserves formatting verbatim.
            depth += line.count("{") - line.count("}")
            if depth == 0:
                end = offset + len(line)
                spans.append((start, end, "".join(block)))
                in_server = False
                block = []
        offset += len(line)
    return spans


def remove_ssl_owned_http_blocks(text: str, domains: Iterable[str]) -> str:
    owned = _normalize_domains(domains)
    if not owned:
        return text
    removals: list[tuple[int, int]] = []
    for start, end, block in _top_level_server_spans(text):
        if not _HTTP_LISTEN_RE.search(block):
            continue
        match = _SERVER_NAME_RE.search(block)
        if match and match.group(1).lower().rstrip(".") in owned:
            removals.append((start, end))
    if not removals:
        return text
    result = text
    for start, end in reversed(removals):
        # Consume at most one following blank line to keep the managed file tidy.
        while end < len(result) and result[end:end + 1] in {"\r", "\n"}:
            end += 1
        result = result[:start] + result[end:]
    return result.rstrip() + "\n"


def discover_ssl_redirect_domains(confd: Path) -> set[str]:
    domains: set[str] = set()
    for path in sorted(confd.glob("dns-manager-ssl-*.conf")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for _, _, block in _top_level_server_spans(text):
            if _HTTP_LISTEN_RE.search(block) and _REDIRECT_RE.search(block):
                match = _SERVER_NAME_RE.search(block)
                if match:
                    domains.add(match.group(1).lower().rstrip("."))
    return domains


def reconcile_file(config: Path, confd: Path) -> bool:
    if not config.is_file():
        return False
    original = config.read_text(encoding="utf-8")
    updated = remove_ssl_owned_http_blocks(original, discover_ssl_redirect_domains(confd))
    if updated == original:
        return False
    fd, tmp_name = tempfile.mkstemp(prefix=f".{config.name}.", dir=config.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(updated)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(tmp_name, config.stat().st_mode & 0o777)
        os.replace(tmp_name, config)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/nginx/conf.d/dns-manager.conf")
    parser.add_argument("--confd", default="/etc/nginx/conf.d")
    args = parser.parse_args(argv)
    changed = reconcile_file(Path(args.config), Path(args.confd))
    print("DNS Manager Nginx mapping dedup: " + ("updated" if changed else "no changes"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
