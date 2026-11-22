"""Deliberately failing email backends for password-reset regression tests (AEMS-010).

Each backend raises the way a real transport does. Messages embed the recipient address, as
``SMTPRecipientsRefused`` does, so tests can prove the address never reaches the logs.
"""

import smtplib
from collections.abc import Sequence
from typing import Any

from django.core.mail.backends.base import BaseEmailBackend


def _recipients(messages: Sequence[Any]) -> list[str]:
    return [address for message in messages for address in message.recipients()]


class RecipientsRefusedBackend(BaseEmailBackend):
    def send_messages(self, email_messages: Sequence[Any]) -> int:
        raise smtplib.SMTPRecipientsRefused(
            dict.fromkeys(_recipients(email_messages), (550, b"mailbox unavailable"))
        )


class ConnectionRefusedBackend(BaseEmailBackend):
    def send_messages(self, email_messages: Sequence[Any]) -> int:
        raise ConnectionRefusedError(f"connection refused for {_recipients(email_messages)}")


class TimeoutBackend(BaseEmailBackend):
    def send_messages(self, email_messages: Sequence[Any]) -> int:
        raise TimeoutError("timed out")


class UnexpectedErrorBackend(BaseEmailBackend):
    def send_messages(self, email_messages: Sequence[Any]) -> int:
        raise RuntimeError(f"unexpected failure while sending to {_recipients(email_messages)}")
