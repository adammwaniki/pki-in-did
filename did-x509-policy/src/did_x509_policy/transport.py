"""How the verifier reaches the network -- and how it behaves when it cannot.

`OfflineTransport` is what `--offline` installs. The container is additionally run with
`docker run --network none`, so the claim is enforced by Docker rather than by this file.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class Transport(Protocol):
    """How the verifier reaches the network. Implement this for any client you prefer.

    `offline` tells the verifier not to expect a network at all, which changes what it says
    when data is missing: "could not be fetched" rather than "unreachable". Both are
    rejections; only the wording differs.

    Any exception raised is treated as "no answer" -- the verifier never distinguishes a
    refused connection from a timeout from a 500, because the decision is the same.
    """

    offline: bool

    def get(self, url: str, *, timeout: float | None = None) -> bytes: ...

    def post(self, url: str, body: bytes, *, content_type: str,
             timeout: float | None = None) -> bytes: ...


class NetworkUnavailable(Exception):
    """No answer from the network: unreachable, refused, timed out, or no network at all."""


class OfflineTransport:
    """There is no network. Every call fails immediately, without touching a socket."""

    offline = True

    def get(self, url: str, *, timeout: float | None = None) -> bytes:
        raise NetworkUnavailable(f"offline: will not fetch {url}")

    def post(self, url: str, body: bytes, *, content_type: str, timeout: float | None = None) -> bytes:
        raise NetworkUnavailable(f"offline: will not post to {url}")


class HttpTransport:
    """Plain HTTP and HTTPS, with a TLS trust store separate from the credential one."""

    offline = False

    def __init__(self, *, tls_bundle: str | None = None, timeout: float = 5.0):
        self.tls_bundle = tls_bundle
        self.timeout = timeout

    def _session(self):
        import requests

        session = requests.Session()
        session.verify = self.tls_bundle if self.tls_bundle else True
        return session

    def get(self, url: str, *, timeout: float | None = None) -> bytes:
        import requests

        try:
            response = self._session().get(url, timeout=timeout or self.timeout)
            response.raise_for_status()
            return response.content
        except requests.RequestException as exc:
            raise NetworkUnavailable(f"GET {url}: {exc}") from exc

    def post(self, url: str, body: bytes, *, content_type: str, timeout: float | None = None) -> bytes:
        import requests

        try:
            response = self._session().post(
                url, data=body, headers={"Content-Type": content_type},
                timeout=timeout or self.timeout,
            )
            response.raise_for_status()
            return response.content
        except requests.RequestException as exc:
            raise NetworkUnavailable(f"POST {url}: {exc}") from exc


def fetch(transport, url: str, *, timeout: float | None = None) -> bytes:
    """GET through any transport, turning every failure into NetworkUnavailable.

    Test transports raise their own exception types; treating any failure as
    "no answer" is both simpler and closer to how a real client behaves.
    """
    try:
        return transport.get(url, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 -- any failure is "no answer"
        raise NetworkUnavailable(str(exc)) from exc


def post(transport, url: str, body: bytes, *, content_type: str, timeout: float | None = None) -> bytes:
    try:
        return transport.post(url, body, content_type=content_type, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        raise NetworkUnavailable(str(exc)) from exc
