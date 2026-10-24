#!/usr/bin/env python3
"""php2shell CVE-2026-109618 quick vulnerability checker.

Two independent signals:

1. PASSIVE (default): PHP version from `X-Powered-By`, compared with the fixed
   releases (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). Sends one ordinary GET.

2. ACTIVE (--active): the behavioural oracle. The vulnerability's precondition
   is PHP's multipart header bloat: before the patch every part header was
   stored (~256 B each), after the patch only `Content-Disposition` and
   `Content-Type` are kept, so the amplification is gone. A body with tens of
   thousands of junk headers therefore

     vulnerable build -> hits memory_limit during request startup
                        (fatal "Allowed memory size ... exhausted" / HTTP 500)
     patched build    -> parses normally, page answers 200

   That differential needs only two HTTP requests and does not rely on the
   worker dying. Worker survival on the same keep-alive connection is reported
   as a secondary signal when the server keeps connections alive.

WARNING: active mode makes the target fail one request (OOM). On a vulnerable
host that can also abort the worker that served it. Use only on hosts you are
authorized to test.

Usage:
  python3 check.py -u https://target/index.php
  python3 check.py -u https://target/index.php --active
  python3 check.py -u https://target/index.php --active --memory-limit 256 --json
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time

FIXED = {"8.1": None, "8.2": (8, 2, 35), "8.3": (8, 3, 36), "8.4": (8, 4, 27), "8.5": (8, 5, 12)}
BOUNDARY = b"----php2shellCHECK"


class Client:
    def __init__(self, url: str, timeout: float = 25.0):
        scheme, _, rest = url.partition("://")
        if scheme not in ("http", "https") or not rest:
            raise SystemExit("url must be http:// or https://")
        self.tls = scheme == "https"
        slash = rest.find("/")
        hostport, self.path = (rest[:slash], rest[slash:]) if slash > 0 else (rest, "/")
        if hostport.startswith("["):                       # ipv6 literal
            host, _, port = hostport.partition("]")
            self.host, self.port = host.lstrip("["), int(port.lstrip(":") or 0) or (443 if self.tls else 80)
        elif ":" in hostport:
            self.host, p = hostport.rsplit(":", 1)
            self.port = int(p)
        else:
            self.host, self.port = hostport, (443 if self.tls else 80)
        self.timeout = timeout

    def connect(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=self.host)
        s.settimeout(self.timeout)
        return s

    def request(self, s, method="GET", path=None, body=b"", ctype=None, keep_alive=True):
        path = path or self.path
        h = [f"{method} {path} HTTP/1.1", f"Host: {self.host}",
             f"Connection: {'keep-alive' if keep_alive else 'close'}",
             "User-Agent: php2shell-check/1.1",
             "Accept: */*"]
        if body:
            h += [f"Content-Type: {ctype}", f"Content-Length: {len(body)}"]
        s.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body)
        return self.read_response(s)

    def read_response(self, s):
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = s.recv(65536)
            if not c:
                return {"status": 0, "headers": {}, "body": buf, "reset": True}
            buf += c
        head, body = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        m = re.match(rb"HTTP/\d\.\d (\d{3})", lines[0]) if lines else None
        status = int(m.group(1)) if m else 0
        headers = {}
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()
        chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        clen = int(headers.get("content-length", "0") or 0)
        try:
            if chunked:
                while not body.endswith(b"0\r\n\r\n"):
                    c = s.recv(65536)
                    if not c:
                        break
                    body += c
            else:
                while len(body) < clen:
                    c = s.recv(65536)
                    if not c:
                        break
                    body += c
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        return {"status": status, "headers": headers, "body": body, "reset": False}


def oom_body(n_headers: int) -> bytes:
    """One multipart part with n junk headers, empty body."""
    out = [b"--" + BOUNDARY + b"\r\n"]
    out.append(b"h0:v\r\n")
    for i in range(1, n_headers):
        out.append(b"h%d:v\r\n" % i)
    out.append(b"\r\n--" + BOUNDARY + b"--\r\n")
    return b"".join(out)


def parse_version(headers: dict):
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", headers.get("x-powered-by", ""))
    return tuple(int(x) for x in m.groups()) if m else None


def version_verdict(v):
    if not v:
        return None
    if v[0] >= 9:
        return "unknown-branch"
    if (v[0], v[1]) < (8, 2):
        return "affected-eol"
    fx = FIXED.get("%d.%d" % (v[0], v[1]))
    if not fx:
        return "unknown-branch"
    return "affected" if v < fx else "fixed"


def classify(checks: dict) -> dict:
    """Decide the active-mode result from the probe response."""
    r = checks.get("probe_response") or {}
    if checks.get("active_error"):
        return {"state": "error", "detail": checks["active_error"]}
    if not r:
        return {"state": "skipped", "detail": "active probe not run"}
    status = r["status"]
    body = (r.get("body_head") or "").lower()
    oom = "allowed memory size" in body or ("memory size" in body and "exhausted" in body)
    if status == 0:
        return {"state": "suspicious",
                "detail": "connection reset during the probe (worker died or server closed) — see retry"}
    if status in (400, 413, 414, 431):
        return {"state": "inconclusive",
                "detail": f"probe rejected (HTTP {status}) — post_max_size/header limits too low"}
    if oom:
        return {"state": "vulnerable",
                "detail": "startup OOM reached with junk multipart headers (amplification active)"}
    if status >= 500:
        return {"state": "suspicious",
                "detail": f"HTTP {status} after the probe, no OOM text (display_errors may be Off)"}
    if status == 200:
        return {"state": "patched",
                "detail": "probe body parsed normally — junk headers are not amplified any more"}
    return {"state": "inconclusive", "detail": f"unexpected HTTP {status}"}


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE-2026-109618 quick check")
    ap.add_argument("-u", "--url", required=True, help="any PHP page on the target")
    ap.add_argument("--active", action="store_true",
                    help="send the OOM/header-amplification probe (needs authorization)")
    ap.add_argument("--memory-limit", type=float, default=128.0,
                    help="assumed memory_limit in MB, sizes the probe (default 128)")
    ap.add_argument("--post-max", type=float, default=8.0,
                    help="assumed post_max_size in MB; the probe body stays below it (default 8)")
    ap.add_argument("--timeout", type=float, default=25.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    c = Client(a.url, a.timeout)
    out = {"target": a.url, "checks": {}, "verdict": "UNKNOWN"}

    # ---------------- passive
    try:
        s = c.connect()
        base = c.request(s, keep_alive=False)
        s.close()
    except OSError as e:
        print(f"[!] cannot connect: {e}", file=sys.stderr)
        return 2

    h = base["headers"]
    ver = parse_version(h)
    out["checks"].update({
        "status": base["status"],
        "server": h.get("server", ""),
        "x_powered_by": h.get("x-powered-by", ""),
        "php_version": ".".join(map(str, ver)) if ver else None,
        "version_verdict": version_verdict(ver),
        "baseline_body_bytes": len(base["body"]),
    })
    is_php = bool(ver) or "php" in h.get("x-powered-by", "").lower()
    out["checks"]["php_detected"] = is_php

    # ---------------- active
    if a.active:
        try:
            s = c.connect()
            # sanity: does the endpoint accept a small multipart POST at all?
            small = oom_body(50)
            r0 = c.request(s, method="POST", body=small,
                           ctype=f"multipart/form-data; boundary={BOUNDARY.decode()}")
            out["checks"]["small_post_status"] = r0["status"]

            keepalive = "keep-alive" in (r0["headers"].get("connection", "") + h.get("connection", "")).lower()
            out["checks"]["keep_alive"] = keepalive

            # size: ~300 B per header inside PHP before the patch
            need = a.memory_limit * 1024 * 1024 * 1.35
            n = max(1000, int(need / 300))
            body = oom_body(n)
            cap = int(a.post_max * 1024 * 1024 * 0.95)
            if len(body) > cap:                     # ~10 wire bytes per header
                n = max(1000, int(cap / 10))
                body = oom_body(n)
            out["checks"]["probe_headers"] = n
            out["checks"]["probe_body_bytes"] = len(body)

            t0 = time.time()
            try:
                r1 = c.request(s, method="POST", body=body,
                               ctype=f"multipart/form-data; boundary={BOUNDARY.decode()}")
            except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as e:
                r1 = {"status": 0, "headers": {}, "body": b"", "reset": True, "err": type(e).__name__}
            dt = time.time() - t0

            out["checks"]["probe_response"] = {
                "status": r1["status"],
                "seconds": round(dt, 2),
                "bytes": len(r1["body"]),
                "reset": r1.get("reset", False),
                "body_head": r1["body"][:400].decode("latin1", "replace"),
            }
            # a reset can simply mean "Connection: keep-alive not honoured";
            # retry once on a fresh, close-only connection to get the body
            if r1["status"] == 0 or r1.get("reset"):
                try:
                    s2 = c.connect()
                    r1b = c.request(s2, method="POST", body=body, keep_alive=False,
                                    ctype=f"multipart/form-data; boundary={BOUNDARY.decode()}")
                    s2.close()
                    out["checks"]["probe_response_retry"] = {
                        "status": r1b["status"], "bytes": len(r1b["body"]),
                        "reset": r1b.get("reset", False),
                        "body_head": r1b["body"][:400].decode("latin1", "replace"),
                    }
                    if r1b["status"]:
                        out["checks"]["probe_response"] = out["checks"]["probe_response_retry"]
                except OSError as e:
                    out["checks"]["probe_response_retry"] = {"error": str(e)}
            active = classify(out["checks"])
            out["checks"]["active"] = active

            # secondary: did the worker survive on this connection?
            if not r1.get("reset") and keepalive:
                try:
                    r2 = c.request(s, keep_alive=True)
                    out["checks"]["worker_survived"] = r2["status"] == 200
                except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
                    out["checks"]["worker_survived"] = False
            s.close()
        except OSError as e:
            out["checks"]["active_error"] = str(e)
            out["checks"]["active"] = {"state": "error", "detail": str(e)}

    # ---------------- verdict
    vv = out["checks"].get("version_verdict")
    act = (out["checks"].get("active") or {}).get("state")
    if act == "vulnerable":
        out["verdict"] = "VULNERABLE (behaviour)"
    elif act == "patched":
        # 200 只证明"这具 body 没把内存打爆"，不证明补丁生效：
        # post_max_size < body 时 PHP 直接跳过 multipart 解析、$_POST 为空但脚本照跑 → 也是 200。
        # 所以版本落在受影响区间时，行为结论不得压过版本，只能报"未证实"。
        if vv in ("affected", "affected-eol"):
            out["verdict"] = "INCONCLUSIVE (behaviour contradicts version: post_max_size skip?)"
        else:
            out["verdict"] = "PATCHED (behaviour)"
    elif act == "suspicious":
        out["verdict"] = "LIKELY VULNERABLE (5xx on probe)" if vv != "fixed" else "SUSPICIOUS (fixed version, 5xx on probe)"
    elif vv in ("affected", "affected-eol"):
        out["verdict"] = "VULNERABLE (version)"
    elif vv == "fixed":
        out["verdict"] = "PATCHED (version)"
    elif not is_php:
        out["verdict"] = "NOT PHP / UNKNOWN"
    else:
        out["verdict"] = "UNKNOWN (version hidden — use --active)"

    if a.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    ck = out["checks"]
    print(f"target        : {a.url}")
    print(f"status        : {ck.get('status')}   server: {ck.get('server','')}")
    print(f"php version   : {ck.get('php_version') or 'hidden'}   [{ck.get('version_verdict') or 'n/a'}]")
    if a.active:
        pr = ck.get("probe_response") or {}
        print(f"keep-alive    : {ck.get('keep_alive')}")
        print(f"probe         : {ck.get('probe_headers')} junk headers / {ck.get('probe_body_bytes')} bytes")
        secs = f" in {pr['seconds']}s" if pr.get("seconds") is not None else ""
        print(f"probe reply   : HTTP {pr.get('status')}{secs}, {pr.get('bytes')}B, reset={pr.get('reset')}")
        if ck.get("probe_response_retry"):
            rr = ck["probe_response_retry"]
            print(f"probe retry   : HTTP {rr.get('status')} {rr.get('bytes')}B reset={rr.get('reset')}")
        if pr.get("body_head"):
            head = " ".join(pr["body_head"].split())[:160]
            print(f"body head     : {head}")
        print(f"active result : {(ck.get('active') or {}).get('state')} — {(ck.get('active') or {}).get('detail')}")
        if "worker_survived" in ck:
            print(f"worker        : survived={ck['worker_survived']} (secondary signal)")
    print(f"VERDICT       : {out['verdict']}")
    print("fixed releases: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (and 8.6 GA)")
    if not a.active:
        print("passive only — add --active for the behavioural probe (authorized hosts only)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
