"""
SecurityBridge — Python Test Suite.

Unit tests validate Python fallback behaviour (no Java bridge required).
Integration tests (marked with @pytest.mark.integration) require a running
Java gateway — skip them with: pytest -m "not integration"
"""

import os
import sys
import re
import pytest

# Add Python source to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
python_src = os.path.join(project_root, "src", "python")
if python_src not in sys.path:
    sys.path.insert(0, python_src)

from security import Security


# =============================================================================
#  Fixtures
# =============================================================================

@pytest.fixture(autouse=True)
def fresh_security():
    """Reset the Security singleton before each test."""
    Security._instance = None
    Security.bridge = None
    sec = Security()
    # Force fallback mode (no Java bridge)
    sec.java_available = False
    return sec


# =============================================================================
#  String Validation — Alphanumeric
# =============================================================================

class TestValidateStringAlphanumeric:

    def test_valid_alphanumeric(self, fresh_security):
        result = fresh_security.validate_string("hello123", "param", "alphanumeric")
        assert result == "hello123"

    def test_underscore_allowed(self, fresh_security):
        result = fresh_security.validate_string("with_underscore", "param", "alphanumeric")
        assert result == "with_underscore"

    def test_rejects_special_chars(self, fresh_security):
        with pytest.raises(ValueError, match="alphanumeric"):
            fresh_security.validate_string("hello!", "param", "alphanumeric")

    def test_rejects_hyphens(self, fresh_security):
        with pytest.raises(ValueError, match="alphanumeric"):
            fresh_security.validate_string("hello-world", "param", "alphanumeric")

    def test_rejects_spaces(self, fresh_security):
        with pytest.raises(ValueError, match="alphanumeric"):
            fresh_security.validate_string("has space", "param", "alphanumeric")

    def test_rejects_none(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be None"):
            fresh_security.validate_string(None, "param", "alphanumeric")


# =============================================================================
#  String Validation — Path
# =============================================================================

class TestValidateStringPath:

    def test_valid_path(self, fresh_security):
        result = fresh_security.validate_string("path/to/file.txt", "param", "path")
        assert result == "path/to/file.txt"

    def test_rejects_traversal_forward(self, fresh_security):
        with pytest.raises(ValueError, match="traversal"):
            fresh_security.validate_string("../etc/passwd", "param", "path")

    def test_rejects_traversal_backslash(self, fresh_security):
        with pytest.raises(ValueError, match="traversal"):
            fresh_security.validate_string("..\\windows\\system32", "param", "path")

    def test_rejects_embedded_traversal(self, fresh_security):
        with pytest.raises(ValueError, match="traversal"):
            fresh_security.validate_string("safe/../../etc/passwd", "param", "path")

    def test_rejects_unsafe_chars(self, fresh_security):
        with pytest.raises(ValueError, match="unsafe path"):
            fresh_security.validate_string("file<name>.txt", "param", "path")

    def test_allows_single_dot(self, fresh_security):
        result = fresh_security.validate_string("file.txt", "param", "path")
        assert result == "file.txt"


# =============================================================================
#  String Validation — Default
# =============================================================================

class TestValidateStringDefault:

    def test_valid_string(self, fresh_security):
        result = fresh_security.validate_string("anything goes!", "param", "default")
        assert result == "anything goes!"

    def test_rejects_empty(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be empty"):
            fresh_security.validate_string("", "param", "default")

    def test_rejects_none(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be None"):
            fresh_security.validate_string(None, "param")


# =============================================================================
#  String Validation — Max Length
# =============================================================================

class TestValidateStringMaxLength:

    def test_rejects_oversized_input(self, fresh_security):
        oversized = "a" * 10_001
        with pytest.raises(ValueError, match="exceeds maximum length"):
            fresh_security.validate_string(oversized, "param", "alphanumeric")

    def test_accepts_max_length_input(self, fresh_security):
        exact = "a" * 10_000
        result = fresh_security.validate_string(exact, "param", "alphanumeric")
        assert result == exact


# =============================================================================
#  Range Validation
# =============================================================================

class TestValidateRange:

    def test_valid_value(self, fresh_security):
        assert fresh_security.validate_range(5, 1, 10, "param") == 5

    def test_boundary_min(self, fresh_security):
        assert fresh_security.validate_range(1, 1, 10, "param") == 1

    def test_boundary_max(self, fresh_security):
        assert fresh_security.validate_range(10, 1, 10, "param") == 10

    def test_rejects_below_min(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be less than"):
            fresh_security.validate_range(0, 1, 10, "param")

    def test_rejects_above_max(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be greater than"):
            fresh_security.validate_range(11, 1, 10, "param")

    def test_rejects_none(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be None"):
            fresh_security.validate_range(None, 1, 10, "param")

    def test_rejects_non_numeric(self, fresh_security):
        with pytest.raises(ValueError, match="must be a numeric"):
            fresh_security.validate_range("abc", 1, 10, "param")

    def test_float_value(self, fresh_security):
        assert fresh_security.validate_range(5.5, 1.0, 10.0, "param") == 5.5


# =============================================================================
#  List Validation
# =============================================================================

class TestValidateList:

    def test_valid_list(self, fresh_security):
        result = fresh_security.validate_list([1, 2, 3], "param")
        assert result == [1, 2, 3]

    def test_valid_tuple(self, fresh_security):
        result = fresh_security.validate_list((1, 2), "param")
        assert result == (1, 2)

    def test_rejects_none(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be None"):
            fresh_security.validate_list(None, "param")

    def test_rejects_non_list(self, fresh_security):
        with pytest.raises(ValueError, match="must be a list"):
            fresh_security.validate_list("not a list", "param")

    def test_min_length(self, fresh_security):
        with pytest.raises(ValueError, match="at least 2"):
            fresh_security.validate_list([1], "param", min_length=2)

    def test_max_length(self, fresh_security):
        with pytest.raises(ValueError, match="more than 2"):
            fresh_security.validate_list([1, 2, 3], "param", max_length=2)


# =============================================================================
#  Configuration Validation
# =============================================================================

class TestValidateConfiguration:

    def test_valid_config(self, fresh_security):
        config = {"key1": "value1", "key2": 42}
        result = fresh_security.validate_configuration("test", config)
        assert result["key1"] == "value1"
        assert result["key2"] == 42

    def test_returns_copy(self, fresh_security):
        config = {"key1": "value1"}
        result = fresh_security.validate_configuration("test", config)
        assert result is not config

    def test_rejects_none_config(self, fresh_security):
        with pytest.raises(ValueError, match="cannot be None"):
            fresh_security.validate_configuration("test", None)

    def test_rejects_non_dict(self, fresh_security):
        with pytest.raises(ValueError, match="must be a dictionary"):
            fresh_security.validate_configuration("test", "not a dict")

    def test_rejects_null_values(self, fresh_security):
        with pytest.raises(ValueError, match="cannot have null value"):
            fresh_security.validate_configuration("test", {"key": None})

    def test_validates_nested_null_values(self, fresh_security):
        config = {"outer": {"inner": None}}
        with pytest.raises(ValueError, match="cannot have null value"):
            fresh_security.validate_configuration("test", config)

    def test_preserves_non_string_types(self, fresh_security):
        config = {"count": 42, "ratio": 3.14, "active": True}
        result = fresh_security.validate_configuration("test", config)
        assert result["count"] == 42
        assert result["ratio"] == 3.14
        assert result["active"] is True


# =============================================================================
#  Security Events
# =============================================================================

class TestRecordSecurityEvent:

    def test_returns_true_on_fallback(self, fresh_security):
        result = fresh_security.record_security_event("test_event", "details", "INFO")
        assert result is True

    def test_accepts_warning_severity(self, fresh_security):
        result = fresh_security.record_security_event("test", "details", "WARNING")
        assert result is True

    def test_accepts_error_severity(self, fresh_security):
        result = fresh_security.record_security_event("test", "details", "ERROR")
        assert result is True


# =============================================================================
#  Integration Tests (require running Java gateway)
# =============================================================================

@pytest.mark.integration
class TestBridgeIntegration:

    @pytest.fixture(autouse=True)
    def bridge_security(self):
        """Create Security instance with real bridge connection."""
        Security._instance = None
        Security.bridge = None
        sec = Security()
        if not sec.java_available:
            pytest.skip("Java bridge not available")
        return sec

    def test_bridge_validates_alphanumeric(self, bridge_security):
        result = bridge_security.validate_string("test123", "param", "alphanumeric")
        assert result == "test123"

    def test_bridge_validates_range(self, bridge_security):
        result = bridge_security.validate_range(50, 0, 100, "param")
        assert result == 50

    def test_bridge_rejects_invalid(self, bridge_security):
        with pytest.raises(ValueError):
            bridge_security.validate_string("bad!", "param", "alphanumeric")


# =============================================================================
#  JWT Validation (Python Fallback)
# =============================================================================

import jwt as pyjwt
import time


class TestValidateJwt:
    """Tests for JWT validation using Python PyJWT fallback."""

    def _make_token(self, claims, secret="test-secret-key-minimum-length-32chars!"):
        return pyjwt.encode(claims, secret, algorithm="HS256")

    def test_valid_token(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user-123", "exp": time.time() + 60})
        claims = sec.validate_jwt(token, secret)
        assert claims["sub"] == "user-123"

    def test_custom_claims(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "admin", "role": "administrator"})
        claims = sec.validate_jwt(token, secret)
        assert claims["sub"] == "admin"
        assert claims["role"] == "administrator"

    def test_issuer_validated(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user", "iss": "auth-service"})
        claims = sec.validate_jwt(token, secret, expected_issuer="auth-service")
        assert claims["iss"] == "auth-service"

    def test_wrong_issuer_rejected(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user", "iss": "wrong-service"})
        with pytest.raises(PermissionError):
            sec.validate_jwt(token, secret, expected_issuer="expected-service")

    def test_audience_validated(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user", "aud": "my-api"})
        claims = sec.validate_jwt(token, secret, expected_audience="my-api")
        assert "my-api" in (claims.get("aud") if isinstance(claims.get("aud"), list)  # type: ignore[operator]
                            else [claims.get("aud")])

    def test_wrong_audience_rejected(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user", "aud": "wrong-api"})
        with pytest.raises(PermissionError):
            sec.validate_jwt(token, secret, expected_audience="expected-api")

    def test_expired_token_rejected(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "user", "exp": time.time() - 300})
        with pytest.raises(PermissionError):
            sec.validate_jwt(token, secret)

    def test_wrong_secret_rejected(self, fresh_security):
        sec = Security()
        token = self._make_token({"sub": "user"})
        with pytest.raises(PermissionError):
            sec.validate_jwt(token, "completely-different-secret-key-here!!")

    def test_malformed_token_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt("not.a.valid.jwt", "secret-key-at-least-32-chars!!!!!")

    def test_garbage_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt("totalgarbage", "secret-key-at-least-32-chars!!!!!")

    def test_empty_token_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt("", "secret")

    def test_none_token_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt(None, "secret")  # type: ignore[arg-type]

    def test_empty_secret_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt("some.jwt.token", "")

    def test_none_secret_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.validate_jwt("some.jwt.token", None)  # type: ignore[arg-type]

    def test_token_without_exp(self, fresh_security):
        sec = Security()
        secret = "test-secret-key-minimum-length-32chars!"
        token = self._make_token({"sub": "service-account"})
        claims = sec.validate_jwt(token, secret)
        assert claims["sub"] == "service-account"


# =============================================================================
#  HTML Sanitization (Python Fallback)
# =============================================================================


class TestSanitizeHtmlStrict:
    """STRICT policy — strips all HTML."""

    def test_strips_all_tags(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<b>Bold</b> <i>Italic</i>", "STRICT")
        assert "<b>" not in result
        assert "<i>" not in result
        assert "Bold" in result
        assert "Italic" in result

    def test_strips_script(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<script>alert('xss')</script>Safe", "STRICT")
        assert "script" not in result.lower()
        assert "Safe" in result

    def test_strips_event_handlers(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<div onclick='steal()'>Click</div>", "STRICT")
        assert "onclick" not in result
        assert "Click" in result

    def test_plain_text_unchanged(self, fresh_security):
        sec = Security()
        assert sec.sanitize_html("Hello World", "STRICT") == "Hello World"


class TestSanitizeHtmlBasic:
    """BASIC policy — formatting tags allowed."""

    def test_allows_bold(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<b>Bold</b>", "BASIC")
        assert "<b>" in result

    def test_allows_italic(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<i>Italic</i>", "BASIC")
        assert "<i>" in result

    def test_allows_lists(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<ul><li>Item</li></ul>", "BASIC")
        assert "<ul>" in result
        assert "<li>" in result

    def test_strips_script(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<b>OK</b><script>bad()</script>", "BASIC")
        assert "<b>" in result
        assert "script" not in result.lower()

    def test_strips_links(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<a href='http://evil.com'>Click</a>", "BASIC")
        assert "<a " not in result


class TestSanitizeHtmlRich:
    """RICH policy — links, images, tables, headings."""

    def test_allows_links(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<a href='https://example.com'>Link</a>", "RICH")
        assert "<a " in result

    def test_allows_images(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html(
            "<img src='https://example.com/img.png' alt='photo'>", "RICH"
        )
        assert "<img " in result

    def test_allows_headings(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<h1>Title</h1><h3>Sub</h3>", "RICH")
        assert "<h1>" in result
        assert "<h3>" in result

    def test_allows_tables(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html(
            "<table><tr><td>Cell</td></tr></table>", "RICH"
        )
        assert "<table>" in result
        assert "<td>" in result

    def test_strips_script(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html(
            "<h1>Title</h1><script>xss()</script>", "RICH"
        )
        assert "<h1>" in result
        assert "script" not in result.lower()


class TestSanitizeHtmlXss:
    """XSS attack vectors."""

    def test_img_onerror(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<img src=x onerror='alert(1)'>", "RICH")
        assert "onerror" not in result

    def test_svg_xss(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html("<svg onload='alert(1)'>test</svg>", "STRICT")
        assert "svg" not in result.lower()
        assert "onload" not in result

    def test_javascript_protocol(self, fresh_security):
        sec = Security()
        result = sec.sanitize_html(
            "<a href='javascript:alert(1)'>Click</a>", "RICH"
        )
        assert "javascript" not in result.lower()


class TestSanitizeHtmlInputValidation:
    """Input edge cases."""

    def test_none_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.sanitize_html(None, "STRICT")  # type: ignore[arg-type]

    def test_empty_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.sanitize_html("", "STRICT")

    def test_unknown_policy_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.sanitize_html("text", "NONEXISTENT")

    def test_oversized_rejected(self, fresh_security):
        sec = Security()
        with pytest.raises(ValueError):
            sec.sanitize_html("x" * 100_001, "STRICT")

    def test_case_insensitive_policy(self, fresh_security):
        sec = Security()
        result1 = sec.sanitize_html("<b>text</b>", "strict")
        result2 = sec.sanitize_html("<b>text</b>", "STRICT")
        assert result1 == result2
