"""
Focused tests for ``validate_redirect_uris`` in the OAuth DCR module.

These tests cover the redirect URI scheme validation behavior introduced by
the OAuth Redirect Schemes plan: defaults are accepted, custom schemes
(e.g. ``cursor``) require explicit operator opt-in via
``MCP_OAUTH_ADDITIONAL_REDIRECT_SCHEMES``, dangerous schemes remain blocked
even if accidentally configured, and the existing per-scheme host rules for
``http`` (loopback only) and ``https`` (host required) are unchanged.
"""

import pytest
from fastapi import HTTPException

from mcp_memory_service.web.oauth import registration
from mcp_memory_service.web.oauth.registration import (
    DEFAULT_ALLOWED_REDIRECT_SCHEMES,
    validate_redirect_uris,
)


# ---------------------------------------------------------------------------
# Defaults accepted (must not raise)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "uri",
    [
        "https://example.com/callback",
        "http://localhost:6274/oauth/callback",
        "http://127.0.0.1:6274/oauth/callback",
        "com.example.app://oauth/callback",
        "myapp://callback",
    ],
)
def test_validate_redirect_uris_accepts_defaults(uri):
    """Default-allowed redirect URI schemes must validate without error."""
    # Should not raise.
    validate_redirect_uris([uri])


def test_validate_redirect_uris_accepts_all_defaults_together():
    """Passing all default-allowed URIs in one call must also succeed."""
    validate_redirect_uris(
        [
            "https://example.com/callback",
            "http://localhost:6274/oauth/callback",
            "http://127.0.0.1:6274/oauth/callback",
            "com.example.app://oauth/callback",
            "myapp://callback",
        ]
    )


# ---------------------------------------------------------------------------
# Cursor rejected by default
# ---------------------------------------------------------------------------

def test_validate_redirect_uris_rejects_cursor_scheme_by_default(monkeypatch):
    """Without operator opt-in, ``cursor://`` must be rejected.

    The error must use the OAuth ``invalid_redirect_uri`` code and the
    description must list the effective allowed schemes (sorted).
    """
    # Ensure no leftover monkeypatching from other tests can pollute this case.
    monkeypatch.setattr(
        registration, "OAUTH_ADDITIONAL_REDIRECT_SCHEMES", frozenset()
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_redirect_uris(["cursor://anysphere.cursor-mcp/oauth/callback"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert isinstance(detail, dict)
    assert detail["error"] == "invalid_redirect_uri"

    description = detail["error_description"]
    # Lists effective allowed schemes, sorted, so operators can see which
    # schemes are loaded and whether a custom one needs to be added.
    sorted_defaults = sorted(DEFAULT_ALLOWED_REDIRECT_SCHEMES)
    listed = ", ".join(sorted_defaults)
    assert listed in description, (
        f"Expected sorted allowed schemes {sorted_defaults!r} in error "
        f"description, got: {description!r}"
    )
    # The error description should also reference the rejected scheme.
    assert "cursor" in description


# ---------------------------------------------------------------------------
# Cursor accepted when configured
# ---------------------------------------------------------------------------

def test_validate_redirect_uris_accepts_cursor_when_configured(monkeypatch):
    """When ``cursor`` is in additional schemes, ``cursor://`` is accepted."""
    monkeypatch.setattr(
        registration,
        "OAUTH_ADDITIONAL_REDIRECT_SCHEMES",
        frozenset({"cursor"}),
    )

    # Should not raise.
    validate_redirect_uris(["cursor://anysphere.cursor-mcp/oauth/callback"])


# ---------------------------------------------------------------------------
# Dangerous schemes rejected even when configured
# ---------------------------------------------------------------------------

def test_validate_redirect_uris_rejects_javascript_even_when_configured(monkeypatch):
    """``javascript:`` must be rejected even if it is in the additional set.

    Dangerous-scheme rejection runs before the allowlist check, so the error
    description must reflect the dangerous-scheme branch (mentions
    "Dangerous"), not the unsupported-scheme branch.
    """
    monkeypatch.setattr(
        registration,
        "OAUTH_ADDITIONAL_REDIRECT_SCHEMES",
        frozenset({"javascript"}),
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_redirect_uris(["javascript:alert(1)"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert detail["error"] == "invalid_redirect_uri"
    # Dangerous-scheme branch wording, not the allowlist branch wording.
    assert "Dangerous" in detail["error_description"]
    assert "javascript" in detail["error_description"]


def test_validate_redirect_uris_rejects_data_uri_even_when_configured(monkeypatch):
    """``data:`` URIs must be rejected even if ``data`` is configured."""
    monkeypatch.setattr(
        registration,
        "OAUTH_ADDITIONAL_REDIRECT_SCHEMES",
        frozenset({"data"}),
    )

    with pytest.raises(HTTPException) as exc_info:
        validate_redirect_uris(["data:text/html,foo"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert detail["error"] == "invalid_redirect_uri"
    assert "Dangerous" in detail["error_description"]
    assert "data" in detail["error_description"]


# ---------------------------------------------------------------------------
# Existing http/https rules unchanged
# ---------------------------------------------------------------------------

def test_validate_redirect_uris_rejects_non_loopback_http():
    """Non-loopback ``http://`` URIs must still be rejected."""
    with pytest.raises(HTTPException) as exc_info:
        validate_redirect_uris(["http://example.com/callback"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert detail["error"] == "invalid_redirect_uri"
    # Localhost-only message wording.
    description = detail["error_description"]
    assert "localhost" in description or "loopback" in description.lower()


def test_validate_redirect_uris_rejects_https_without_host():
    """``https://`` with no host must still be rejected."""
    with pytest.raises(HTTPException) as exc_info:
        validate_redirect_uris(["https://"])

    assert exc_info.value.status_code == 400
    detail = exc_info.value.detail
    assert detail["error"] == "invalid_redirect_uri"
    assert "host" in detail["error_description"].lower()
