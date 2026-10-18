from __future__ import annotations
import json, os, socket
from typing import Callable
from privileged.helper_lib import HelperOps
from privileged.ssl_helper import SslHelperOps
from privileged.acme_dns_helper import AcmeDnsHelperOps
from privileged.firewall_helper import FirewallHelperOps

LEGACY={"validate","apply","rollback","status"}
SSL_FIELDS={
 "ssl_status":{"domain"}, "ssl_apply":{"domain","redirect_http","upstream"}, "ssl_delete":{"domain"},
 "ssl_issue":{"domain","provider","token"}, "ssl_renew":{"domain","provider","token","force"}, "ssl_test_renewal":{"domain","provider","token"}, "ssl_manual_continue":{"domain"}, "ssl_manual_status":{"domain"}
}
FIREWALL_FIELDS={"firewall_status":set(),"firewall_preview":{"policy"},"firewall_apply":{"policy"},"firewall_confirm":{"token"},"firewall_rollback":{"token"}}
ACME_FIELDS={"acme_dns_status":set(), "acme_zone_check":set(), "acme_txt_set":{"hostname","value"}, "acme_txt_delete":{"hostname","value"}}
MAX_REQUEST_BYTES=16384

def handle_request(request:str, ops=None, acme_ops=None)->dict:
    try:
        if request in LEGACY:
            target=ops or HelperOps(); result=getattr(target,request)(); return {"ok":True,**result}
        payload=json.loads(request); command=payload.pop("command")
        if command in FIREWALL_FIELDS:
            if set(payload)-FIREWALL_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
            target=FirewallHelperOps()
            method={"firewall_status":"status","firewall_preview":"preview","firewall_apply":"apply","firewall_confirm":"confirm","firewall_rollback":"rollback"}[command]
            arg = payload.get("policy") if command in {"firewall_preview","firewall_apply"} else payload.get("token")
            result = getattr(target,method)() if command=="firewall_status" else getattr(target,method)(arg)
            return {"ok":True,**result}
        if command in ACME_FIELDS:
            if set(payload)-ACME_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
            target=acme_ops or AcmeDnsHelperOps()
            method={"acme_dns_status":"status","acme_zone_check":"zone_check","acme_txt_set":"txt_set","acme_txt_delete":"txt_delete"}[command]
            result=getattr(target,method)(**payload); return {"ok":True,**result}
        if command not in SSL_FIELDS or set(payload)-SSL_FIELDS[command]: return {"ok":False,"error":"unsupported privileged helper command"}
        target=ops or SslHelperOps(); result=getattr(target,command)(**payload); return {"ok":True,**result}
    except Exception as exc: return {"ok":False,"error":str(exc)}

def _read_request(conn:socket.socket)->str:
    data=bytearray()
    while b"\n" not in data:
        part=conn.recv(4096)
        if not part: break
        data.extend(part)
        if len(data)>MAX_REQUEST_BYTES:return ""
    try:return bytes(data).split(b"\n",1)[0].decode("utf-8",errors="strict")
    except UnicodeDecodeError:return ""

def systemd_listener()->socket.socket:
    if int(os.environ.get("LISTEN_FDS","0"))<1: raise RuntimeError("no systemd socket passed")
    listen_pid=int(os.environ.get("LISTEN_PID","0"))
    if listen_pid not in (0,os.getpid()): raise RuntimeError("systemd socket belongs to another process")
    return socket.fromfd(3,socket.AF_UNIX,socket.SOCK_STREAM)

def serve_once(listener:socket.socket,ops_factory:Callable[[],HelperOps]=HelperOps)->None:
    conn,_=listener.accept()
    with conn:
        request=_read_request(conn)
        payload=handle_request(request, ops_factory() if request in LEGACY else None)
        try:
            conn.sendall((json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n").encode())
        except (BrokenPipeError, ConnectionResetError):
            return

def serve_forever(listener=None,ops_factory=HelperOps)->None:
    listener=listener or systemd_listener()
    while True:serve_once(listener,ops_factory)
