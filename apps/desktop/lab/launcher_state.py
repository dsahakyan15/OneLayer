"""Bounded, credential-free reachability probes for the Linux demo launcher.

Availability is a point-in-time HTTP observation, not an authenticated session,
chain trust verdict, or permission to publish. No environment URL overrides,
cookies, proxies, redirects, tokens, process control, or auto-start behavior.
"""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection, HTTPException
import json
import socket
import threading
import time
from urllib.parse import urlsplit


SERVICE_LABELS = {
    "api": "Data service",
    "verifier": "Verifier",
    "web": "Web workspace",
}
HEALTH_STATES = {
    "unknown": "Not checked",
    "loading": "Checking…",
    "available": "Available",
    "offline": "Unavailable",
    "error": "Invalid response",
}
_ENDPOINTS = (
    ("api", "http://127.0.0.1:8090/v1/health", True),
    ("verifier", "http://127.0.0.1:8080/v1/health", True),
    ("web", "http://127.0.0.1:8091/", False),
)
_TIMEOUT = 2
_MAX_HEALTH_BYTES = 4096


def _probe(url, json_health):
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        return {"state": "error", "detail": "Invalid service address"}
    # Direct HTTPConnection ignores environment proxies and never follows
    # redirects. An absolute deadline also interrupts a slowly streamed body,
    # rather than extending the wait after every byte received.
    connection = HTTPConnection("127.0.0.1", parsed.port, timeout=_TIMEOUT)
    deadline = time.monotonic() + _TIMEOUT
    timer = None
    try:
        connection.connect()
        transport = connection.sock

        def interrupt():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        connection.request("GET", parsed.path or "/", headers={
            "Accept": "application/json" if json_health else "text/html",
        })
        with connection.getresponse() as response:
            if response.status != 200:
                return {"state": "error", "detail": f"HTTP {response.status}"}
            if json_health:
                raw = response.read(_MAX_HEALTH_BYTES + 1)
                if len(raw) > _MAX_HEALTH_BYTES:
                    return {"state": "error", "detail": "Response too large"}
                body = json.loads(raw)
                if not isinstance(body, dict) or body.get("status") != "ok":
                    return {"state": "error", "detail": "Service did not confirm availability"}
            return {"state": "available", "detail": "Response received at the last check"}
    except (TimeoutError, OSError):
        return {"state": "offline", "detail": "No response from the local service"}
    except HTTPException:
        return {"state": "error", "detail": "Invalid service response"}
    except (ValueError, UnicodeError, RecursionError):
        return {"state": "error", "detail": "Invalid service response"}
    finally:
        if timer:
            timer.cancel()
        connection.close()


def probe_services():
    """Return all three independent observations; call outside the GTK thread."""
    with ThreadPoolExecutor(max_workers=len(_ENDPOINTS)) as workers:
        pending = [(key, workers.submit(_probe, url, is_json)) for key, url, is_json in _ENDPOINTS]
        return {key: future.result() for key, future in pending}
