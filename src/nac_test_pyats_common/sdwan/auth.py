# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SDWAN Manager authentication implementation for Cisco SD-WAN.

This module provides authentication functionality for Cisco SDWAN Manager (formerly
vManage), which manages the software-defined WAN fabric. Two authentication methods
are supported:

1. **Session auth** (all versions): Form-based login with JSESSIONID cookie and
   optional XSRF token for CSRF protection.
2. **API token auth** (20.18+): Bearer token authentication using a pre-generated
   JWT. The CSRF token is extracted from the JWT payload. No network call is needed
   for authentication — the token is provided via the SDWAN_API_TOKEN environment
   variable.

When SDWAN_API_TOKEN is set, it takes priority over username/password credentials.

The module implements a two-tier API design:
1. _authenticate() - Low-level method that performs direct SDWAN Manager authentication
2. _authenticate_with_api_token() - Low-level method for JWT-based authentication
3. get_auth() - High-level method that leverages caching for efficient token reuse

This design ensures efficient session management by reusing valid sessions and only
re-authenticating when necessary, reducing unnecessary API calls to the SDWAN Manager.

Note on Fork Safety:
    The session auth path uses urllib instead of httpx for synchronous authentication
    requests. httpx is NOT fork-safe on macOS - creating httpx.Client after fork()
    causes silent crashes due to OpenSSL threading issues. urllib uses simpler
    primitives that work correctly after fork(). The API token path does not require
    any network calls, so fork safety is not a concern.
"""

import base64
import json
import logging
import os
from typing import Any

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    SubprocessAuthError,  # noqa: F401 - re-exported for callers to catch
    execute_auth_subprocess,
)

logger = logging.getLogger(__name__)

# Default session lifetime for SDWAN Manager session authentication in seconds
# SDWAN Manager sessions are typically valid for 30 minutes (1800 seconds) by default
SDWAN_MANAGER_SESSION_LIFETIME_SECONDS: int = 1800

# Default cache lifetime for API token authentication in seconds
# API tokens have their own expiration (set by admin), but we cache the decoded
# result for 1 hour to avoid re-decoding on every test. The JWT itself is validated
# server-side on each request, so an expired token will fail at request time.
SDWAN_API_TOKEN_CACHE_LIFETIME_SECONDS: int = 3600

# HTTP timeout for XSRF token fetch (shorter than auth timeout since it's optional)
XSRF_TOKEN_FETCH_TIMEOUT_SECONDS: float = 10.0

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0

# Authentication script body executed in a subprocess via execute_auth_subprocess.
# Extracted as a module-level constant so unit tests can compile and execute it
# directly with mocked urllib, closing the test gap identified in PR #29 review.
#
# Contract:
#   Input:  `params` dict with keys: url, username, password, timeout,
#           xsrf_timeout, verify_ssl
#   Output: `result` dict with either:
#           - {"jsessionid": str, "xsrf_token": str | None}  (success)
#           - {"error": str}                                   (failure)
_AUTH_SCRIPT_BODY: str = """
import http.cookiejar
import ssl
import urllib.parse
import urllib.request

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]
xsrf_timeout = params["xsrf_timeout"]
verify_ssl = params["verify_ssl"]

# Create SSL context
ssl_context = ssl.create_default_context()
if not verify_ssl:
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

# Create cookie jar and opener
cookie_jar = http.cookiejar.CookieJar()
https_handler = urllib.request.HTTPSHandler(context=ssl_context)
cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
opener = urllib.request.build_opener(https_handler, cookie_handler)

# Step 1: Form-based login to /j_security_check
auth_data = urllib.parse.urlencode({
    "j_username": username,
    "j_password": password
}).encode("utf-8")

auth_request = urllib.request.Request(
    f"{url}/j_security_check",
    data=auth_data,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST"
)

auth_body = None

try:
    auth_response = opener.open(auth_request, timeout=timeout)
    auth_body = auth_response.read().decode("utf-8", errors="replace")
except urllib.error.HTTPError as e:
    if e.code == 302:
        # 302 redirect is expected on successful login
        auth_body = ""
    elif e.code in (401, 403):
        # Defensive: SD-WAN Manager currently returns 200+HTML for bad creds,
        # but if Cisco ever fixes the API to return proper HTTP errors, handle
        # them gracefully instead of falling through to the HTML check.
        result = {
            "error": (
                f"Authentication failed - HTTP {e.code}: {e.reason}. "
                "Verify SDWAN_USERNAME and SDWAN_PASSWORD are correct."
            )
        }
    else:
        # Other HTTP errors (500, 502, etc.) - server/network issue, not creds
        error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        err_snippet = error_body[:200]
        result = {
            "error": (
                f"Authentication request failed - HTTP {e.code}: {e.reason}. "
                f"{err_snippet}"
            ).strip()
        }
except Exception as e:
    # Network-level errors (socket.timeout, URLError, SSLError, OSError, etc.)
    result = {
        "error": f"Authentication request failed - network error: {e}"
    }

if auth_body is not None:
    # SD-WAN Manager returns HTTP 200 with an HTML login page on auth failure
    # (it never returns 401/403). Successful login returns HTTP 200 with an empty body.
    if auth_body and "<html" in auth_body.lower():
        result = {
            "error": (
                "Authentication failed - SD-WAN Manager returned the login page. "
                "Verify SDWAN_USERNAME and SDWAN_PASSWORD are correct."
            )
        }
    else:
        # Extract JSESSIONID from cookies
        jsessionid = None
        for cookie in cookie_jar:
            if cookie.name == "JSESSIONID":
                jsessionid = cookie.value
                break

        if jsessionid is None:
            result = {
                "error": (
                    "No JSESSIONID cookie received - authentication may have failed"
                )
            }
        else:
            # Step 2: Fetch XSRF token (required for SDWAN Manager 19.2+)
            xsrf_token = None
            try:
                token_request = urllib.request.Request(
                    f"{url}/dataservice/client/token",
                    headers={"Cookie": f"JSESSIONID={jsessionid}"},
                    method="GET"
                )
                token_response = opener.open(token_request, timeout=xsrf_timeout)
                content_type = token_response.headers.get("Content-Type", "")
                if token_response.status == 200 and "text/html" not in content_type:
                    token_body = token_response.read().decode("utf-8").strip()
                    # Defense-in-depth: real XSRF tokens are hex strings, not HTML
                    if token_body and "<html" not in token_body.lower():
                        xsrf_token = token_body
            except Exception:
                pass  # Pre-19.2 versions do not support XSRF tokens

            result = {"jsessionid": jsessionid, "xsrf_token": xsrf_token, "auth_type": "session"}
"""


class SDWANManagerAuth:
    """SDWAN Manager authentication implementation with session caching.

    This class provides a two-tier API for SDWAN Manager authentication:

    1. Low-level _authenticate() method: Directly authenticates with SDWAN Manager using
       form-based login and returns session data along with expiration time. This is
       typically used by the caching layer and not called directly by consumers.

    2. High-level get_auth() method: Provides cached session management, automatically
       handling session renewal when expired. This is the primary method that consumers
       should use for obtaining SDWAN Manager authentication data.

    The authentication flow supports:
    - Pre-19.2 versions: JSESSIONID cookie only
    - 19.2+ versions: JSESSIONID cookie plus X-XSRF-TOKEN header for CSRF protection
    - 20.18+ versions: API token (JWT) with Bearer authorization and X-XSRF-TOKEN

    When SDWAN_API_TOKEN is set, token-based auth takes priority over
    username/password credentials.

    Example:
        >>> # Session auth
        >>> auth_data = SDWANManagerAuth.get_auth()
        >>> headers = {"Cookie": f"JSESSIONID={auth_data['jsessionid']}"}
        >>> if auth_data.get("xsrf_token"):
        ...     headers["X-XSRF-TOKEN"] = auth_data["xsrf_token"]
        >>>
        >>> # Token auth (20.18+) — set SDWAN_API_TOKEN env var, then:
        >>> auth_data = SDWANManagerAuth.get_auth()
        >>> headers = {"Authorization": f"Bearer {auth_data['api_token']}"}
        >>> headers["X-XSRF-TOKEN"] = auth_data["csrf_token"]
    """

    @staticmethod
    def _authenticate(
        url: str, username: str, password: str, verify_ssl: bool = False
    ) -> tuple[dict[str, Any], int]:
        """Perform direct SDWAN Manager authentication and obtain session data.

        This method performs a direct authentication request to the SDWAN Manager
        using form-based login. It returns both the session data and its lifetime
        for proper cache management.

        The authentication process:
        1. POST form credentials to /j_security_check endpoint
        2. Extract JSESSIONID cookie from response
        3. Attempt to fetch XSRF token (for 19.2+ only)
        4. Return session data with TTL

        Note: On macOS, SSL operations in forked processes crash due to OpenSSL
        threading issues. This method uses subprocess with spawn context to perform
        authentication in a fresh process, avoiding the fork+SSL crash.

        Args:
            url: Base URL of the SDWAN Manager (e.g., "https://sdwan-manager.example.com").
                Should not include trailing slashes or API paths.
            username: SDWAN Manager username for authentication. This should be a valid
                user configured with appropriate permissions.
            password: Password for the specified user account.
            verify_ssl: Whether to verify SSL certificates. Defaults to False to
                handle self-signed certificates commonly used in lab and development
                deployments.

        Returns:
            A tuple containing:
                - auth_dict (dict): Dictionary with 'jsessionid' (str) and 'xsrf_token'
                  (str | None). The xsrf_token is None for pre-19.2 versions.
                - expires_in (int): Session lifetime in seconds (typically 1800).

        Raises:
            SubprocessAuthError: If authentication subprocess fails.
            ValueError: If the authentication response is malformed.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "xsrf_timeout": XSRF_TOKEN_FETCH_TIMEOUT_SECONDS,
            "verify_ssl": verify_ssl,
        }

        # Execute authentication in subprocess (fork-safe on macOS)
        auth_result = execute_auth_subprocess(auth_params, _AUTH_SCRIPT_BODY)

        return {
            "jsessionid": auth_result["jsessionid"],
            "xsrf_token": auth_result.get("xsrf_token"),
            "auth_type": "session",
        }, SDWAN_MANAGER_SESSION_LIFETIME_SECONDS

    @staticmethod
    def _authenticate_with_api_token(
        api_token: str,
    ) -> tuple[dict[str, Any], int]:
        """Authenticate using a pre-generated API token (JWT) for SD-WAN 20.18+.

        This method decodes the JWT payload to extract the CSRF token without
        making any network calls. The JWT is validated server-side on each API
        request, so no upfront validation against the controller is performed.

        The JWT payload is expected to contain a 'csrf' field. The token format
        is: header.payload.signature (standard JWT structure).

        Args:
            api_token: The JWT API token string (e.g., from SDWAN_API_TOKEN
                environment variable).

        Returns:
            A tuple containing:
                - auth_dict (dict): Dictionary with 'api_token' (str),
                  'csrf_token' (str), and 'auth_type' set to 'token'.
                - expires_in (int): Cache lifetime in seconds.

        Raises:
            ValueError: If the token is not a valid JWT or is missing the
                'csrf' field in its payload.
        """
        try:
            parts = api_token.split(".")
            if len(parts) != 3:  # noqa: PLR2004
                raise ValueError(
                    "SDWAN_API_TOKEN is not a valid JWT: expected 3 dot-separated "
                    "parts (header.payload.signature), "
                    f"got {len(parts)}."
                )
            payload_b64 = parts[1]
            # Add padding for base64 decoding
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except (json.JSONDecodeError, UnicodeDecodeError, Exception) as e:
            if isinstance(e, ValueError):
                raise
            raise ValueError(
                "Failed to decode SDWAN_API_TOKEN: not a valid JWT. "
                "Verify the token format (header.payload.signature)."
            ) from e

        csrf_token = payload.get("csrf", "")
        if not csrf_token:
            raise ValueError(
                "SDWAN_API_TOKEN is missing 'csrf' field in JWT payload. "
                "Verify the token was generated correctly."
            )

        logger.info("Using API token authentication (SD-WAN 20.18+)")

        return {
            "api_token": api_token,
            "csrf_token": csrf_token,
            "auth_type": "token",
        }, SDWAN_API_TOKEN_CACHE_LIFETIME_SECONDS

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """Get SDWAN Manager authentication data with automatic caching and renewal.

        This is the primary method that consumers should use to obtain SDWAN Manager
        authentication data. It leverages the AuthCache to efficiently manage
        session lifecycle, reusing valid sessions and automatically renewing
        expired ones. This significantly reduces the number of authentication
        requests to the SDWAN Manager.

        The method uses a cache key based on the controller type ("SDWAN_MANAGER")
        and URL to ensure proper session isolation between different SDWAN Manager
        instances.

        Environment Variables:
            SDWAN_API_TOKEN: (Optional) JWT API token for 20.18+ token-based auth.
                When set, takes priority over username/password. SDWAN_URL is still
                required.
            SDWAN_URL: Base URL of the SDWAN Manager (always required).
            SDWAN_USERNAME: SDWAN Manager username (required for session auth).
            SDWAN_PASSWORD: SDWAN Manager password (required for session auth).
            SDWAN_INSECURE: If "True", "1", or "yes" (default: "True"), SSL certificate
                verification is disabled. Set to "False" to enable SSL verification.
                Only used for session auth.

        Returns:
            A dictionary containing auth data. The 'auth_type' key indicates the
            method used:

            For session auth (auth_type='session'):
                - jsessionid (str): The session cookie value
                - xsrf_token (str | None): The XSRF token (None for pre-19.2)
                - auth_type (str): 'session'

            For token auth (auth_type='token'):
                - api_token (str): The Bearer token for Authorization header
                - csrf_token (str): The CSRF token extracted from JWT payload
                - auth_type (str): 'token'

        Raises:
            ValueError: If required environment variables are missing, or if
                SDWAN_API_TOKEN is not a valid JWT / missing 'csrf' field.
            SubprocessAuthError: If session authentication fails due to invalid
                credentials, network issues, or server errors.
        """
        url = os.environ.get("SDWAN_URL")
        api_token = os.environ.get("SDWAN_API_TOKEN", "").strip()

        if not url:
            raise ValueError(
                "Missing required environment variable: SDWAN_URL"
            )

        # Normalize URL by removing trailing slash
        url = url.rstrip("/")

        # API token takes priority over username/password when both are set
        if api_token:
            def token_auth_wrapper() -> tuple[dict[str, Any], int]:
                """Wrapper for API token authentication."""
                return cls._authenticate_with_api_token(api_token)

            return AuthCache.get_or_create(  # type: ignore[no-any-return]
                controller_type="SDWAN_MANAGER_TOKEN",
                url=url,
                auth_func=token_auth_wrapper,
            )

        # Fall back to session-based authentication
        username = os.environ.get("SDWAN_USERNAME")
        password = os.environ.get("SDWAN_PASSWORD")
        insecure = os.environ.get("SDWAN_INSECURE", "True").lower() in (
            "true",
            "1",
            "yes",
        )

        if not all([username, password]):
            missing_vars: list[str] = []
            if not username:
                missing_vars.append("SDWAN_USERNAME")
            if not password:
                missing_vars.append("SDWAN_PASSWORD")
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}. "
                "Provide SDWAN_API_TOKEN for token auth, or SDWAN_USERNAME and "
                "SDWAN_PASSWORD for session auth."
            )

        # SDWAN_INSECURE=True means verify_ssl=False
        verify_ssl = not insecure

        def auth_wrapper() -> tuple[dict[str, Any], int]:
            """Wrapper for authentication that captures closure variables."""
            return cls._authenticate(url, username, password, verify_ssl)  # type: ignore[arg-type]

        # AuthCache.get_or_create returns dict[str, Any], but mypy can't verify this
        # because nac_test lacks py.typed marker.
        return AuthCache.get_or_create(  # type: ignore[no-any-return]
            controller_type="SDWAN_MANAGER",
            url=url,
            auth_func=auth_wrapper,
        )
