"""Loopback-only integration transport. NOT external-browser/native SSO.

The backend still owns PKCE, JWT validation and session authority. This test
user-agent keeps its cookie jar and CSRF token in memory; the UI receives only
a sanitized session summary. Never enable this transport for a real issuer.
"""
import http.cookiejar
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPCookieProcessor, ProxyHandler, Request, build_opener


class SessionFailure(Exception):
    def __init__(self, state):
        super().__init__(state)
        self.state = state


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def loopback_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or
            not parsed.port or parsed.username or parsed.password or
            parsed.path or parsed.query or parsed.fragment):
        raise ValueError("Only explicit synthetic IPv4 loopback origins are allowed")
    return value


class LabSession:
    def __init__(self, backend, issuer):
        self._backend = loopback_origin(backend)
        self._issuer = loopback_origin(issuer)
        if self._backend == self._issuer:
            raise ValueError("Separate backend and test issuer origins required")
        self._cookies = http.cookiejar.CookieJar()
        self._http = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(self._cookies))
        # The issuer must never receive backend cookies (cookies do not isolate ports).
        self._idp_http = build_opener(ProxyHandler({}), NoRedirect())
        self._csrf = None

    def _request(self, url, method="GET", issuer=False):
        headers = {} if issuer else {"Origin": self._backend}
        if not issuer and self._csrf:
            headers["x-onelayer-csrf"] = self._csrf
        try:
            response = (self._idp_http if issuer else self._http).open(
                Request(url, method=method, headers=headers), timeout=5)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError, OSError):
            raise SessionFailure("offline") from None
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise SessionFailure("error")
            return response.status, response.headers, raw

    def login(self):
        self.clear()
        try:
            status, _, raw = self._request(self._backend + "/v2/admin/oidc/start", "POST")
            if status != 200:
                raise SessionFailure("error")
            target = json.loads(raw)["authorizationUrl"]
            parsed = urlsplit(target)
            if f"{parsed.scheme}://{parsed.netloc}" != self._issuer or parsed.path != "/authorize" or parsed.fragment:
                raise SessionFailure("error")
            status, headers, _ = self._request(target, issuer=True)
            callback = headers.get("location", "")
            parsed = urlsplit(callback)
            if status != 302 or f"{parsed.scheme}://{parsed.netloc}" != self._backend or parsed.path != "/v2/admin/oidc/callback" or parsed.fragment:
                raise SessionFailure("error")
            status, _, _ = self._request(callback)
            if status != 200:
                raise SessionFailure("expired")
            return self.refresh()
        except (KeyError, ValueError, TypeError):
            self.clear()
            raise SessionFailure("error") from None
        except SessionFailure:
            self.clear()
            raise

    def refresh(self):
        try:
            status, _, raw = self._request(self._backend + "/v1/admin/session")
            if status == 401:
                self.clear()
                raise SessionFailure("expired")
            if status != 200:
                raise SessionFailure("error")
            body = json.loads(raw)
            if any(not isinstance(body.get(key), str) or not body[key] for key in ("username", "role", "csrfToken")):
                raise SessionFailure("error")
            self._csrf = body["csrfToken"]
            return {"username": body["username"], "role": body["role"]}
        except (ValueError, TypeError):
            self.clear()
            raise SessionFailure("error") from None

    def logout(self):
        try:
            status, _, _ = self._request(self._backend + "/v1/admin/session", "DELETE")
            if status not in (204, 401):
                raise SessionFailure("error")
        finally:
            self.clear()

    def clear(self):
        self._cookies.clear()
        self._csrf = None
