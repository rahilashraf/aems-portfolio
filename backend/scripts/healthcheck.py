"""Container health probe for the production image (Docker ``HEALTHCHECK``).

Django rejects requests whose ``Host`` header is not in ``ALLOWED_HOSTS``. In production that list
normally contains only the public API domain, so probing ``http://127.0.0.1:8000`` with a
``127.0.0.1`` Host header fails host validation. Instead of widening ``ALLOWED_HOSTS`` or
bypassing host validation, the probe connects to the local socket but presents the first
configured allowed host as the ``Host`` header, so the request goes through normal validation.

Standard library only; exits 0 when ``/health/live/`` returns HTTP 200, otherwise 1.
"""

import http.client
import os
import sys
from collections.abc import Mapping

PROBE_ADDRESS = "127.0.0.1"
PROBE_PORT = 8000
PROBE_PATH = "/health/live/"
PROBE_TIMEOUT_SECONDS = 4.0


def resolve_probe_host(environ: Mapping[str, str]) -> str:
    """Return the Host header to present: the first usable entry of DJANGO_ALLOWED_HOSTS.

    A leading dot (``.example.org``, Django's subdomain wildcard) is stripped, since the bare
    domain matches it. Wildcards are never used; production settings reject ``*`` anyway.
    """
    for raw in environ.get("DJANGO_ALLOWED_HOSTS", "").split(","):
        host = raw.strip().lstrip(".")
        if host and host != "*":
            return host
    msg = "DJANGO_ALLOWED_HOSTS has no usable host for the health probe."
    raise ValueError(msg)


def probe(
    host_header: str,
    *,
    address: str = PROBE_ADDRESS,
    port: int = PROBE_PORT,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> bool:
    """Return True if the liveness endpoint answers HTTP 200 for ``host_header``."""
    connection = http.client.HTTPConnection(address, port, timeout=timeout)
    try:
        connection.request("GET", PROBE_PATH, headers={"Host": host_header})
        return connection.getresponse().status == http.client.OK
    except OSError:
        return False
    finally:
        connection.close()


def main(environ: Mapping[str, str] | None = None) -> int:
    env = os.environ if environ is None else environ
    try:
        host = resolve_probe_host(env)
    except ValueError as exc:
        sys.stderr.write(f"healthcheck: {exc}\n")
        return 1
    return 0 if probe(host) else 1


if __name__ == "__main__":
    sys.exit(main())
