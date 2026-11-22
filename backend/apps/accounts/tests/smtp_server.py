"""A minimal in-process SMTP server for delivery tests (ADR-0014).

It speaks just enough SMTP for :mod:`smtplib` and Django's SMTP backend. It can accept mail, reject
recipients, or stall before its greeting (to provoke client timeouts). It counts connections, so
tests can prove that the request path never contacts the mail server.
"""

import socketserver
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import Message
from typing import Any


@dataclass
class SmtpBehaviour:
    greeting_delay: float = 0.0
    reject_recipients: bool = False


@dataclass
class SmtpLog:
    connections: int = 0
    messages: list[Message] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _Handler(socketserver.StreamRequestHandler):
    server: "_Server"

    def _reply(self, line: str) -> None:
        self.wfile.write(f"{line}\r\n".encode())
        self.wfile.flush()

    def handle(self) -> None:
        behaviour, log = self.server.behaviour, self.server.log
        with log.lock:
            log.connections += 1
        if behaviour.greeting_delay:
            time.sleep(behaviour.greeting_delay)
        self._reply("220 test-smtp ready")
        while line := self.rfile.readline():
            command = line.decode(errors="replace").strip().upper()
            if command.startswith(("EHLO", "HELO")):
                self._reply("250 test-smtp")
            elif command.startswith("RCPT"):
                self._reply("550 mailbox unavailable" if behaviour.reject_recipients else "250 OK")
            elif command == "DATA":
                self._reply("354 end with <CRLF>.<CRLF>")
                self._receive_data(log)
                self._reply("250 queued")
            elif command == "QUIT":
                self._reply("221 bye")
                return
            else:  # MAIL, RSET, NOOP
                self._reply("250 OK")

    def _receive_data(self, log: SmtpLog) -> None:
        lines: list[bytes] = []
        while (line := self.rfile.readline()) not in (b".\r\n", b""):
            lines.append(line[1:] if line.startswith(b"..") else line)
        with log.lock:
            log.messages.append(message_from_bytes(b"".join(lines)))


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Clients that time out close the socket mid-conversation; that is expected here."""

    def __init__(self, behaviour: SmtpBehaviour, log: SmtpLog) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.behaviour = behaviour
        self.log = log


@contextmanager
def smtp_server(**behaviour: Any) -> Iterator[tuple[dict[str, Any], SmtpLog]]:
    """Run a server; yields (Django email settings, log)."""
    log = SmtpLog()
    server = _Server(SmtpBehaviour(**behaviour), log)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = {
            "EMAIL_BACKEND": "django.core.mail.backends.smtp.EmailBackend",
            "EMAIL_HOST": "127.0.0.1",
            "EMAIL_PORT": server.server_address[1],
            "EMAIL_USE_TLS": False,
            "EMAIL_USE_SSL": False,
            "EMAIL_HOST_USER": "",
            "EMAIL_HOST_PASSWORD": "",
        }
        yield settings, log
    finally:
        server.shutdown()
        server.server_close()
