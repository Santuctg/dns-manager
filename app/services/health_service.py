from __future__ import annotations

import http.client
import socket
import ssl
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.config import get_settings, load_hosted_acme_config
from app.database import get_engine
from app.models.mapping import Mapping
from app.services.privileged_helper import PrivilegedHelper
from app.services.dns_safety import get_dns_safety_status

DEFAULT_BACKEND_TIMEOUT = 3.0
MAX_BACKEND_TIMEOUT = 10.0


def database_health() -> str:
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return "error"
    return "ok"


def _port_open(host: str | None, port: int, timeout: float = 0.4) -> bool:
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False




def hosted_acme_health() -> dict[str, Any]:
    cfg=load_hosted_acme_config()
    if not cfg.enabled:
        return {'configured':False,'server_url':cfg.server_url,'reachable':False}
    from urllib.parse import urlsplit
    parts=urlsplit(cfg.server_url)
    host=parts.hostname
    port=parts.port or 443
    reachable=False
    try:
        context=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=min(cfg.http_timeout,5.0)) as raw:
            with context.wrap_socket(raw,server_hostname=host):
                reachable=True
    except OSError:
        reachable=False
    return {'configured':True,'server_url':cfg.server_url,'reachable':reachable}


def get_system_status(helper: PrivilegedHelper | None = None) -> dict[str, Any]:
    helper = helper or PrivilegedHelper()
    db_state = database_health()
    try:
        service_state = helper.status()
    except Exception:
        service_state = {"dnsmasq": "unknown", "nginx": "unknown"}

    proxy_ip = get_settings().internal_proxy_ip
    dns_safety = get_dns_safety_status()
    ports = {
        "53": _port_open(proxy_ip, 53),
        "80": _port_open(proxy_ip, 80),
        "443": _port_open(proxy_ip, 443),
    }
    try:
        acme_dns = helper.acme_dns_status()
    except Exception:
        acme_dns = {"configured": False, "service":"unknown", "zone":None, "zone_loaded":False, "listen_ip":None, "tcp_53":False, "udp_53":False}
    ready = (
        db_state == "ok"
        and service_state.get("dnsmasq") == "active"
        and service_state.get("nginx") == "active"
        and ports["53"]
        and ports["80"]
        and dns_safety.get("safe") is True
    )
    return {
        "status": "ready" if ready else "not_ready",
        "database": db_state,
        "dnsmasq": service_state.get("dnsmasq", "unknown"),
        "nginx": service_state.get("nginx", "unknown"),
        "ports": ports,
        "dns_safety": dns_safety,
        "acme_dns": acme_dns,
        "hosted_acme_dns": hosted_acme_health(),
    }


def _backend_timeout(mapping: Mapping, timeout: float | None) -> float:
    if timeout is not None:
        return max(0.05, float(timeout))
    configured = float(mapping.custom_timeout or DEFAULT_BACKEND_TIMEOUT)
    return max(0.05, min(configured, MAX_BACKEND_TIMEOUT))


def check_backend(mapping: Mapping, *, timeout: float | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mapping_id": mapping.id,
        "domain": mapping.domain,
        "status": "UNKNOWN",
        "latency_ms": None,
        "http_status": None,
        "detail": None,
    }
    if not mapping.enabled:
        result["detail"] = "mapping disabled"
        return result

    started = time.monotonic()
    conn: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    try:
        request_timeout = _backend_timeout(mapping, timeout)
        headers = {
            "Host": mapping.domain if mapping.preserve_host else mapping.upstream_host,
            "Connection": "close",
        }
        if mapping.upstream_scheme == "https":
            context = ssl.create_default_context()
            if not mapping.tls_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(
                mapping.upstream_host,
                mapping.upstream_port,
                timeout=request_timeout,
                context=context,
            )
        elif mapping.upstream_scheme == "http":
            conn = http.client.HTTPConnection(
                mapping.upstream_host,
                mapping.upstream_port,
                timeout=request_timeout,
            )
        else:
            result["detail"] = "unsupported upstream scheme"
            return result

        conn.request("HEAD", "/", headers=headers)
        response = conn.getresponse()
        result["http_status"] = int(response.status)
        response.read()
        result["status"] = "HTTP_ERROR" if response.status >= 500 else "UP"
        if response.status >= 500:
            result["detail"] = f"HTTP {response.status}"
    except ssl.SSLError as exc:
        result["status"] = "TLS_ERROR"
        result["detail"] = str(exc)
    except (socket.timeout, TimeoutError) as exc:
        result["status"] = "TIMEOUT"
        result["detail"] = str(exc) or "backend timed out"
    except (ConnectionRefusedError, ConnectionResetError, socket.gaierror, OSError) as exc:
        result["status"] = "DOWN"
        result["detail"] = str(exc)
    except Exception as exc:
        result["status"] = "UNKNOWN"
        result["detail"] = str(exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        result["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result
