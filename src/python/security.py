"""
SecurityBridge — Python Security API.

Provides a Pythonic interface to the Java security bridge with automatic
Python fallbacks when the bridge is unavailable. The fallback implementations
mirror the Java behaviour as closely as possible.

Usage:
    from security import Security, get_instance

    sec = get_instance()
    clean_name = sec.validate_string(username, "username", "alphanumeric")
    clean_path = sec.validate_string(filepath, "filepath", "path")
    valid_port = sec.validate_range(port, 1, 65535, "port")
    claims     = sec.validate_jwt(token, secret)
    safe_html  = sec.sanitize_html(untrusted_html, "BASIC")
"""

import logging
import re
import os
from typing import Any, Dict, Optional

# --- Constants ----------------------------------------------------------------

# Matches Java's ValidationUtils.ALPHANUMERIC_PATTERN: [a-zA-Z0-9_]
_ALPHANUMERIC_RE = re.compile(r"^[a-zA-Z0-9_]*$")

# Maximum input string length (mirrors Java's ValidationUtils.MAX_INPUT_LENGTH)
_MAX_INPUT_LENGTH = 10_000

# Maximum HTML input length (mirrors Java's HtmlSanitizer.MAX_HTML_LENGTH)
_MAX_HTML_LENGTH = 100_000

# Tags allowed per sanitization policy (Python fallback via nh3)
_NH3_STRICT_TAGS: set[str] = set()
_NH3_BASIC_TAGS: set[str] = {
    "b", "i", "em", "strong", "u", "br", "p", "ul", "ol", "li",
    "blockquote", "sub", "sup", "s", "strike",
}
_NH3_RICH_TAGS: set[str] = _NH3_BASIC_TAGS | {
    "a", "img", "table", "thead", "tbody", "tr", "th", "td",
    "h1", "h2", "h3", "h4", "h5", "h6",
}

# Attributes allowed per policy (Python fallback via nh3)
_NH3_BASIC_ATTRS: dict[str, set[str]] = {}
_NH3_RICH_ATTRS: dict[str, set[str]] = {
    "a": {"href", "title"},
    "img": {"src", "alt", "width", "height"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
}

# --- Optional imports ---------------------------------------------------------

try:
    from security_bridge import get_instance as get_bridge_instance
    from security_bridge import SecurityBridge
except ImportError:
    logging.getLogger(__name__).warning(
        "Could not import security_bridge. Will use Python fallback implementations."
    )
    get_bridge_instance = None
    SecurityBridge = None

try:
    import jwt as pyjwt
except ImportError:
    logging.getLogger(__name__).warning(
        "PyJWT not installed. JWT fallback will not be available."
    )
    pyjwt = None

try:
    import nh3
except ImportError:
    logging.getLogger(__name__).warning(
        "nh3 not installed. HTML sanitization fallback will not be available."
    )
    nh3 = None


class Security:
    """
    Security utility providing validation with Java bridge and Python fallbacks.

    Implemented as a singleton to match Java SecurityManager's pattern.
    When the Java bridge is available, all validation is delegated to the
    JVM. When unavailable, Python fallbacks are used with behaviour aligned
    to the Java implementations.
    """

    _instance = None
    _logger = logging.getLogger(__name__)

    # Class-level bridge reference (can be overridden in tests)
    bridge: Any = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Security, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize the security utility and attempt bridge connection."""
        self._logger.info("Initializing Security utility")
        self.java_available = False

        if get_bridge_instance is None:
            self._logger.warning(
                "security_bridge module not available, using Python fallbacks"
            )
            return

        try:
            Security.bridge = get_bridge_instance()
            self.java_available = Security.bridge.java_available
            if self.java_available:
                self._logger.info("Java security bridge available and connected")
            else:
                self._logger.warning(
                    "Java security bridge unavailable, using Python fallbacks"
                )
        except Exception as e:
            self._logger.warning(f"Failed to initialize Java security bridge: {e}")
            self.java_available = False
            Security.bridge = None

    # =========================================================================
    #  String Validation
    # =========================================================================

    def validate_string(self, input_str, param_name, validation_type="default"):
        """
        Validate a string input.

        Supported validation types:
            - "default"      — non-empty check only
            - "alphanumeric" — letters, digits, and underscore [a-zA-Z0-9_]
            - "path"         — filesystem-safe characters, no traversal

        Args:
            input_str:       The string to validate.
            param_name:      Parameter name for error messages.
            validation_type: Validation type to apply.

        Returns:
            The validated string (unchanged).

        Raises:
            ValueError: If validation fails.
        """
        if input_str is None:
            raise ValueError(f"{param_name} cannot be None")

        if len(input_str) > _MAX_INPUT_LENGTH:
            raise ValueError(
                f"{param_name} exceeds maximum length of {_MAX_INPUT_LENGTH} characters"
            )

        # Path safety checks run regardless of bridge availability
        if validation_type == "path":
            self._check_path_safety(input_str, param_name)

        # Delegate to Java bridge if available
        if self.java_available and Security.bridge:
            try:
                return Security.bridge.validate_string(
                    input_str, param_name, validation_type
                )
            except Exception as e:
                self._logger.warning(
                    f"Java validation failed, falling back to Python: {e}"
                )

        # Python fallback
        return self._validate_string_fallback(input_str, param_name, validation_type)

    def _check_path_safety(self, input_str, param_name):
        """Enforce path traversal and escape checks (always applied)."""
        if ".." in input_str:
            raise ValueError(f"{param_name} contains directory traversal sequence")

        if input_str.startswith("/"):
            norm_path = os.path.normpath(input_str)
            cwd = os.getcwd()
            if not norm_path.startswith(cwd):
                raise ValueError(f"{param_name} points outside permitted directory")

    def _validate_string_fallback(self, input_str, param_name, validation_type):
        """Python fallback validation matching Java behaviour."""
        if validation_type == "alphanumeric":
            if not _ALPHANUMERIC_RE.match(input_str):
                raise ValueError(
                    f"{param_name} must be alphanumeric "
                    f"(letters, digits, underscore only)"
                )
        elif validation_type == "path":
            if any(c in input_str for c in '<>:"|?*'):
                raise ValueError(f"{param_name} contains unsafe path characters")
        else:
            if not input_str:
                raise ValueError(f"{param_name} cannot be empty")

        return input_str

    # =========================================================================
    #  Numeric Validation
    # =========================================================================

    def validate_range(self, value, min_val, max_val, param_name):
        """
        Validate that a numeric value falls within an inclusive range.

        Args:
            value:      The value to validate.
            min_val:    Minimum allowed value (inclusive).
            max_val:    Maximum allowed value (inclusive).
            param_name: Parameter name for error messages.

        Returns:
            The validated value (original type preserved).

        Raises:
            ValueError: If the value is None, non-numeric, or out of range.
        """
        if value is None:
            raise ValueError(f"{param_name} cannot be None")

        # Delegate to Java bridge if available
        if self.java_available and Security.bridge:
            try:
                return Security.bridge.validate_range(
                    value, min_val, max_val, param_name
                )
            except Exception as e:
                self._logger.warning(
                    f"Java validation failed, falling back to Python: {e}"
                )

        # Python fallback
        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{param_name} must be a numeric value")

        if numeric_value < min_val:
            raise ValueError(f"{param_name} cannot be less than {min_val}")
        if numeric_value > max_val:
            raise ValueError(f"{param_name} cannot be greater than {max_val}")

        return value

    # =========================================================================
    #  List Validation
    # =========================================================================

    def validate_list(self, value, param_name, min_length=None, max_length=None):
        """
        Validate a list or tuple with optional length constraints.

        Args:
            value:      The list/tuple to validate.
            param_name: Parameter name for error messages.
            min_length: Minimum required length (optional).
            max_length: Maximum allowed length (optional).

        Returns:
            The validated list/tuple (unchanged).

        Raises:
            ValueError: If validation fails.
        """
        if value is None:
            raise ValueError(f"{param_name} cannot be None")

        if not isinstance(value, (list, tuple)):
            raise ValueError(f"{param_name} must be a list or tuple")

        if min_length is not None and len(value) < min_length:
            raise ValueError(
                f"{param_name} must have at least {min_length} elements"
            )

        if max_length is not None and len(value) > max_length:
            raise ValueError(
                f"{param_name} cannot have more than {max_length} elements"
            )

        return value

    # =========================================================================
    #  Configuration Validation
    # =========================================================================

    def validate_configuration(self, config_type, config):
        """
        Validate a configuration dictionary.

        Checks for null values, then delegates to the Java bridge or
        applies Python fallback validation (type-checking and string
        sanitisation on each entry).

        Args:
            config_type: Configuration type identifier.
            config:      Configuration dictionary to validate.

        Returns:
            A validated copy of the configuration.

        Raises:
            ValueError: If validation fails.
        """
        if config is None:
            raise ValueError(f"Configuration for {config_type} cannot be None")

        if not isinstance(config, dict):
            raise ValueError(f"Configuration for {config_type} must be a dictionary")

        # Reject null values
        for key, value in config.items():
            if value is None:
                raise ValueError(f"Configuration key '{key}' cannot have null value")

        # Delegate to Java bridge if available
        if self.java_available and Security.bridge:
            try:
                return Security.bridge.validate_configuration(config_type, config)
            except Exception as e:
                self._logger.warning(
                    f"Java configuration validation failed, falling back to Python: {e}"
                )

        # Python fallback — validate each entry and return a copy
        validated = {}
        for key, value in config.items():
            if isinstance(value, str):
                validated[key] = self.validate_string(value, f"config.{key}")
            elif isinstance(value, (list, tuple)):
                validated[key] = self.validate_list(value, f"config.{key}")
            elif isinstance(value, dict):
                for nested_key, nested_value in value.items():
                    if nested_value is None:
                        raise ValueError(
                            f"Configuration key '{key}.{nested_key}' "
                            f"cannot have null value"
                        )
                validated[key] = value
            else:
                validated[key] = value

        return validated

    # =========================================================================
    #  JWT Validation
    # =========================================================================

    def validate_jwt(
        self,
        token: str,
        secret: str,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate a JWT token signed with HMAC (HS256/HS384/HS512).

        Delegates to the Java bridge when available (Nimbus JOSE), otherwise
        falls back to PyJWT.

        Args:
            token:             The compact JWT string.
            secret:            The HMAC shared secret.
            expected_issuer:   Required ``iss`` claim, or None to skip.
            expected_audience: Required ``aud`` claim, or None to skip.

        Returns:
            Parsed claims as a Python dictionary.

        Raises:
            ValueError:      If the token is malformed or a claim is invalid.
            PermissionError: If signature verification or auth checks fail.
            RuntimeError:    If no JWT library is available.
        """
        if not token:
            raise ValueError("token cannot be None or empty")
        if not secret:
            raise ValueError("secret cannot be None or empty")

        # Delegate to Java bridge
        if self.java_available and Security.bridge:
            try:
                return Security.bridge.validate_jwt(
                    token, secret, expected_issuer, expected_audience
                )
            except Exception as e:
                self._logger.warning(
                    f"Java JWT validation failed, falling back to Python: {e}"
                )

        # Python fallback
        return self._validate_jwt_fallback(
            token, secret, expected_issuer, expected_audience
        )

    def _validate_jwt_fallback(
        self,
        token: str,
        secret: str,
        expected_issuer: Optional[str],
        expected_audience: Optional[str],
    ) -> Dict[str, Any]:
        """Python JWT fallback using PyJWT."""
        if pyjwt is None:
            raise RuntimeError(
                "No JWT library available: Java bridge is down and PyJWT is not installed"
            )

        algorithms = ["HS256", "HS384", "HS512"]
        options: Dict[str, Any] = {}
        kwargs: Dict[str, Any] = {
            "algorithms": algorithms,
            "options": options,
        }

        if expected_issuer:
            kwargs["issuer"] = expected_issuer
        if expected_audience:
            kwargs["audience"] = expected_audience

        try:
            claims = pyjwt.decode(token, secret, **kwargs)
            return dict(claims)
        except pyjwt.exceptions.ExpiredSignatureError as e:
            raise PermissionError(f"JWT expired: {e}")
        except pyjwt.exceptions.InvalidSignatureError as e:
            raise PermissionError(f"JWT signature invalid: {e}")
        except pyjwt.exceptions.InvalidIssuerError as e:
            raise PermissionError(f"JWT issuer invalid: {e}")
        except pyjwt.exceptions.InvalidAudienceError as e:
            raise PermissionError(f"JWT audience invalid: {e}")
        except pyjwt.exceptions.ImmatureSignatureError as e:
            raise PermissionError(f"JWT not yet valid: {e}")
        except pyjwt.exceptions.DecodeError as e:
            raise ValueError(f"JWT malformed: {e}")
        except pyjwt.exceptions.InvalidTokenError as e:
            raise ValueError(f"JWT validation failed: {e}")

    # =========================================================================
    #  HTML Sanitization
    # =========================================================================

    def sanitize_html(self, html: str, policy_name: str = "STRICT") -> str:
        """
        Sanitize untrusted HTML using the named policy.

        Delegates to the Java bridge when available (OWASP HTML Sanitizer),
        otherwise falls back to nh3.

        Policies:
            - ``STRICT`` — strips all HTML, returns plain text
            - ``BASIC``  — allows formatting tags (b, i, em, p, ul, ol, etc.)
            - ``RICH``   — allows BASIC plus links, images, tables, headings

        Args:
            html:        The untrusted HTML string.
            policy_name: Policy to apply (case-insensitive).

        Returns:
            The sanitized HTML string.

        Raises:
            ValueError:    If input is None, empty, too long, or policy unknown.
            RuntimeError:  If no sanitization library is available.
        """
        if not html:
            raise ValueError("html cannot be None or empty")
        if len(html) > _MAX_HTML_LENGTH:
            raise ValueError(
                f"HTML input exceeds maximum length of {_MAX_HTML_LENGTH} characters"
            )

        # Delegate to Java bridge
        if self.java_available and Security.bridge:
            try:
                return Security.bridge.sanitize_html(html, policy_name)
            except Exception as e:
                self._logger.warning(
                    f"Java HTML sanitization failed, falling back to Python: {e}"
                )

        # Python fallback
        return self._sanitize_html_fallback(html, policy_name)

    def _sanitize_html_fallback(self, html: str, policy_name: str) -> str:
        """Python HTML sanitization fallback using nh3."""
        if nh3 is None:
            raise RuntimeError(
                "No HTML sanitizer available: Java bridge is down and nh3 is not installed"
            )

        policy = policy_name.upper()

        if policy == "STRICT":
            return nh3.clean(html, tags=_NH3_STRICT_TAGS)
        elif policy == "BASIC":
            return nh3.clean(html, tags=_NH3_BASIC_TAGS, attributes=_NH3_BASIC_ATTRS)
        elif policy == "RICH":
            return nh3.clean(
                html,
                tags=_NH3_RICH_TAGS,
                attributes=_NH3_RICH_ATTRS,
                link_rel=None,
            )
        else:
            raise ValueError(
                f"Unknown sanitization policy: '{policy_name}'. "
                f"Available: STRICT, BASIC, RICH"
            )

    # =========================================================================
    #  Security Events
    # =========================================================================

    def record_security_event(self, event_type, details, severity="INFO"):
        """
        Record a security event via Java bridge or Python logging fallback.

        Args:
            event_type: Event type identifier.
            details:    Human-readable event details.
            severity:   Log level — "INFO", "WARNING", or "ERROR".

        Returns:
            True if the event was recorded successfully.
        """
        self.validate_string(event_type, "event_type")
        self.validate_string(details, "details")

        if self.java_available and Security.bridge:
            try:
                return Security.bridge.record_security_event(
                    event_type, details, severity
                )
            except Exception as e:
                self._logger.warning(
                    f"Failed to record security event via Java: {e}"
                )

        # Python fallback
        log_message = f"Security Event [{event_type}]: {details}"

        if severity == "ERROR":
            self._logger.error(log_message)
        elif severity == "WARNING":
            self._logger.warning(log_message)
        else:
            self._logger.info(log_message)

        return True


def get_instance():
    """Return the singleton Security instance."""
    return Security()
