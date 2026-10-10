"""HTTP client for the GhidraMCP Java backend."""

from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urljoin

import requests

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_CONNECT_TIMEOUT = 5.0
# Must outlast the backend's decompiler timeout (60 s).
DEFAULT_READ_TIMEOUT = 90.0


class BackendError(Exception):
    """A failure reported by (or while reaching) the Java backend."""

    def __init__(self, code: str, message: str, status: int | None = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status = status


class GhidraBackend:
    def __init__(
        self,
        base_url: str = DEFAULT_GHIDRA_SERVER,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = DEFAULT_READ_TIMEOUT,
    ):
        self.base_url = base_url
        self.timeout = (connect_timeout, read_timeout)
        self.session = requests.Session()
        # Never route loopback traffic through an HTTP proxy from the environment.
        self.session.trust_env = False

    @property
    def base_url(self) -> str:
        return self._base_url

    @base_url.setter
    def base_url(self, value: str) -> None:
        self._base_url = value if value.endswith("/") else value + "/"

    def get(self, endpoint: str, **params: Any) -> Any:
        return self.request("GET", endpoint, params)

    def post(self, endpoint: str, **params: Any) -> Any:
        return self.request("POST", endpoint, params)

    def request(self, method: str, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        """Calls the backend and returns the response's `data`, or raises BackendError."""
        params = {k: v for k, v in (params or {}).items() if v is not None}
        url = urljoin(self.base_url, endpoint.lstrip("/"))
        try:
            if method == "GET":
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(url, data=params, timeout=self.timeout)
        except requests.ConnectionError as e:
            raise BackendError(
                "BACKEND_UNAVAILABLE",
                f"Cannot reach the GhidraMCP backend at {self.base_url}. Is Ghidra running with "
                f"the GhidraMCP plugin enabled and a program open? ({e.__class__.__name__})",
            ) from e
        except requests.Timeout as e:
            raise BackendError(
                "BACKEND_TIMEOUT", f"The GhidraMCP backend did not respond within {self.timeout[1]}s"
            ) from e
        except requests.RequestException as e:
            raise BackendError("BACKEND_UNAVAILABLE", str(e)) from e

        try:
            body = response.json()
        except ValueError:
            raise BackendError(
                "BAD_RESPONSE",
                f"Backend returned non-JSON (HTTP {response.status_code}). An older GhidraMCP "
                f"plugin may be installed; update the Ghidra extension.",
                response.status_code,
            ) from None
        if not isinstance(body, dict) or "success" not in body:
            raise BackendError("BAD_RESPONSE", "Backend response is missing 'success'")
        if not body["success"]:
            error = body.get("error") or {}
            raise BackendError(
                error.get("code", "UNKNOWN_ERROR"),
                error.get("message", "Unknown backend error"),
                response.status_code,
            )
        return body.get("data")

    def health(self, timeout: float = 2.0) -> dict | None:
        """Returns the backend's /health data, or None if it cannot be reached."""
        saved = self.timeout
        self.timeout = (timeout, timeout)
        try:
            return self.get("health")
        except BackendError:
            return None
        finally:
            self.timeout = saved


class DeferredBackend(GhidraBackend):
    """A backend whose URL becomes known later (headless mode, while the program loads)."""

    def __init__(self, connect_timeout: float, read_timeout: float, wait_timeout: float):
        super().__init__("http://127.0.0.1:0/", connect_timeout, read_timeout)
        self.wait_timeout = wait_timeout
        self._ready = threading.Event()
        self._failure: str | None = None
        self.status = "starting"

    def set_ready(self, base_url: str) -> None:
        self.base_url = base_url
        self.status = "ready"
        self._ready.set()

    def set_failed(self, message: str) -> None:
        self._failure = message
        self.status = "failed"
        self._ready.set()

    def request(self, method: str, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        if not self._ready.wait(self.wait_timeout):
            raise BackendError(
                "NOT_READY",
                f"The program is still being loaded or analyzed ({self.status}). Retry shortly.",
            )
        if self._failure is not None:
            raise BackendError("HEADLESS_FAILED", self._failure)
        return super().request(method, endpoint, params)
