"""
SecurityBridge — Py4J Client.

Singleton bridge connecting Python to the Java SecurityManager via Py4J.
This is a client-only bridge — it calls Java methods but does not require
Java to call back into Python, so no callback server is started.

Usage:
    from security_bridge import get_instance

    bridge = get_instance()
    if bridge.java_available:
        result = bridge.validate_string("hello", "name", "alphanumeric")
        claims = bridge.validate_jwt(token, secret)
        clean  = bridge.sanitize_html("<script>xss</script>Hi", "STRICT")
"""

from typing import Any
import logging
import os

from py4j.java_gateway import JavaGateway, GatewayParameters
from py4j.protocol import Py4JJavaError, Py4JNetworkError


class SecurityBridge:
    """
    Singleton Py4J client for the Java SecurityManager.

    Connects to an already-running Java gateway on port 25333 using an
    auth token from the ``SECURITYBRIDGE_AUTH_TOKEN`` environment variable.

    If the gateway is not running or connection fails, ``java_available``
    is set to ``False`` and callers should use Python fallbacks (handled
    automatically by :class:`security.Security`).
    """

    _instance = None
    _logger = logging.getLogger(__name__)

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SecurityBridge, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Connect to the Java gateway and obtain a SecurityManager reference."""
        self._logger.info("Initializing SecurityBridge client")
        self.java_available: bool = False
        self.security_manager: Any = None
        self.gateway: Any = None

        auth_token = os.environ.get("SECURITYBRIDGE_AUTH_TOKEN")

        try:
            self.gateway = JavaGateway(
                gateway_parameters=GatewayParameters(
                    auto_convert=True,
                    enable_memory_management=True,
                    auth_token=auth_token,
                ),
                start_callback_server=False,
            )

            # Obtain the singleton SecurityManager from the JVM
            self.security_manager = (
                self.gateway.jvm.com.securitybridge.SecurityManager.getInstance()
            )
            self.java_available = True
            self._logger.info("SecurityBridge connected to Java SecurityManager")

        except Py4JNetworkError as e:
            self._logger.warning(f"Java gateway not reachable: {e}")
        except Py4JJavaError as e:
            self._logger.error(f"Java error during bridge init: {e.java_exception}")
        except Exception as e:
            self._logger.error(f"Failed to initialise SecurityBridge: {e}")

    # =========================================================================
    #  String Validation
    # =========================================================================

    def validate_string(self, input_str, param_name, validation_type="default"):
        """
        Validate a string via Java SecurityManager.validateString().

        Args:
            input_str:       The string to validate.
            param_name:      Parameter name for error messages.
            validation_type: "default", "alphanumeric", or "path".

        Returns:
            The validated string.

        Raises:
            RuntimeError:    If the Java bridge is unavailable.
            ValueError:      If Java validation rejects the input.
            PermissionError: If a Java SecurityException is raised.
        """
        self._require_bridge()

        try:
            return self.security_manager.validateString(
                input_str, param_name, validation_type
            )
        except Py4JJavaError as e:
            raise self._translate_java_error(e, "Validation error")

    # =========================================================================
    #  Numeric Validation
    # =========================================================================

    def validate_range(self, value, min_val, max_val, param_name):
        """
        Validate a numeric value via Java SecurityManager.validateRange().

        Args:
            value:      The value to validate.
            min_val:    Minimum allowed (inclusive).
            max_val:    Maximum allowed (inclusive).
            param_name: Parameter name for error messages.

        Returns:
            The validated value.

        Raises:
            RuntimeError: If the Java bridge is unavailable.
            ValueError:   If the value is out of range.
        """
        self._require_bridge()

        try:
            return self.security_manager.validateRange(
                value, min_val, max_val, param_name
            )
        except Py4JJavaError as e:
            raise self._translate_java_error(e, "Range validation error")

    # =========================================================================
    #  Configuration Validation
    # =========================================================================

    def validate_configuration(self, config_type, config):
        """
        Validate a config dict via Java SecurityManager.validateConfiguration().

        Args:
            config_type: Configuration type identifier.
            config:      Configuration dictionary.

        Returns:
            The validated configuration (may be a sanitised copy).

        Raises:
            RuntimeError: If the Java bridge is unavailable.
            ValueError:   If configuration validation fails.
        """
        self._require_bridge()

        try:
            return self.security_manager.validateConfiguration(config_type, config)
        except Py4JJavaError as e:
            raise self._translate_java_error(e, "Configuration validation error")

    # =========================================================================
    #  JWT Validation
    # =========================================================================

    def validate_jwt(self, token, secret, expected_issuer=None, expected_audience=None):
        """
        Validate a JWT token via Java SecurityManager.validateJwt().

        Args:
            token:             The compact JWT string.
            secret:            The HMAC shared secret.
            expected_issuer:   Required issuer claim, or None to skip.
            expected_audience: Required audience claim, or None to skip.

        Returns:
            dict: Parsed claims as a Python dictionary.

        Raises:
            RuntimeError:    If the Java bridge is unavailable.
            ValueError:      If the token is malformed or claims are invalid.
            PermissionError: If signature verification fails.
        """
        self._require_bridge()

        try:
            if expected_issuer or expected_audience:
                java_map = self.security_manager.validateJwt(
                    token, secret, expected_issuer, expected_audience
                )
            else:
                java_map = self.security_manager.validateJwt(token, secret)
            return dict(java_map)
        except Py4JJavaError as e:
            raise self._translate_jwt_error(e)

    def validate_jwt_rsa(self, token, public_key_pem,
                         expected_issuer=None, expected_audience=None):
        """
        Validate an RSA-signed JWT via Java SecurityManager.validateJwtRsa().

        Args:
            token:             The compact JWT string.
            public_key_pem:    RSA public key in PEM or raw Base64 format.
            expected_issuer:   Required issuer claim, or None to skip.
            expected_audience: Required audience claim, or None to skip.

        Returns:
            dict: Parsed claims as a Python dictionary.

        Raises:
            RuntimeError:    If the Java bridge is unavailable.
            ValueError:      If the token is malformed or claims are invalid.
            PermissionError: If signature verification fails.
        """
        self._require_bridge()

        try:
            java_map = self.security_manager.validateJwtRsa(token, public_key_pem)
            return dict(java_map)
        except Py4JJavaError as e:
            raise self._translate_jwt_error(e)

    # =========================================================================
    #  HTML Sanitization
    # =========================================================================

    def sanitize_html(self, html, policy_name="STRICT"):
        """
        Sanitize HTML via Java SecurityManager.sanitizeHtml().

        Args:
            html:        The untrusted HTML string.
            policy_name: "STRICT", "BASIC", "RICH", or a custom policy.

        Returns:
            str: The sanitized HTML.

        Raises:
            RuntimeError: If the Java bridge is unavailable.
            ValueError:   If the input or policy is invalid.
        """
        self._require_bridge()

        try:
            return self.security_manager.sanitizeHtml(html, policy_name)
        except Py4JJavaError as e:
            raise self._translate_java_error(e, "Sanitization error")

    # =========================================================================
    #  Security Events
    # =========================================================================

    def record_security_event(self, event_type, details, severity):
        """
        Record a security event via Java SecurityManager.recordSecurityEvent().

        Args:
            event_type: Event type identifier.
            details:    Human-readable event details.
            severity:   "INFO", "WARNING", or "ERROR".

        Returns:
            True if recorded successfully, False otherwise.
        """
        if not self.java_available:
            self._logger.warning(
                f"Cannot record security event (no bridge): {event_type}"
            )
            return False

        try:
            self.security_manager.recordSecurityEvent(event_type, details, severity)
            return True
        except Py4JJavaError as e:
            self._logger.error(f"Failed to record security event: {e.java_exception}")
            return False

    # =========================================================================
    #  Lifecycle
    # =========================================================================

    def close(self):
        """Close the Py4J gateway connection."""
        if self.gateway is not None:
            try:
                self.gateway.close()
                self._logger.info("SecurityBridge connection closed")
            except Exception as e:
                self._logger.error(f"Error closing SecurityBridge: {e}")
            finally:
                self.gateway: Any = None
                self.java_available: bool = False
                self.security_manager: Any = None

    # =========================================================================
    #  Internal Helpers
    # =========================================================================

    def _require_bridge(self):
        """Raise RuntimeError if the Java bridge is not available."""
        if not self.java_available:
            raise RuntimeError("Java Security Bridge unavailable")

    def _translate_java_error(self, error, context):
        """
        Translate a Py4JJavaError into the appropriate Python exception.

        Maps:
            IllegalArgumentException → ValueError
            SecurityException        → PermissionError
            Everything else          → RuntimeError
        """
        java_msg = str(error.java_exception)

        if "IllegalArgumentException" in java_msg:
            return ValueError(f"{context}: {java_msg}")
        elif "SecurityException" in java_msg:
            return PermissionError(f"Security error: {java_msg}")
        else:
            return RuntimeError(f"Java error: {java_msg}")

    def _translate_jwt_error(self, error):
        """
        Translate a JWT-specific Py4JJavaError into a Python exception.

        Maps:
            JwtValidationException(MALFORMED_TOKEN)       → ValueError
            JwtValidationException(INVALID_SIGNATURE)     → PermissionError
            JwtValidationException(EXPIRED)               → PermissionError
            JwtValidationException(NOT_YET_VALID)         → PermissionError
            JwtValidationException(INVALID_ISSUER)        → PermissionError
            JwtValidationException(INVALID_AUDIENCE)      → PermissionError
            JwtValidationException(UNSUPPORTED_ALGORITHM) → ValueError
            JwtValidationException(INVALID_KEY)           → RuntimeError
            IllegalArgumentException                      → ValueError
            IllegalStateException                         → RuntimeError
            Everything else                               → RuntimeError
        """
        java_msg = str(error.java_exception)

        if "IllegalArgumentException" in java_msg:
            return ValueError(f"Invalid input: {java_msg}")
        elif "IllegalStateException" in java_msg:
            return RuntimeError(f"Security disabled: {java_msg}")
        elif "MALFORMED_TOKEN" in java_msg or "UNSUPPORTED_ALGORITHM" in java_msg:
            return ValueError(f"JWT validation failed: {java_msg}")
        elif any(reason in java_msg for reason in (
            "INVALID_SIGNATURE", "EXPIRED", "NOT_YET_VALID",
            "INVALID_ISSUER", "INVALID_AUDIENCE",
        )):
            return PermissionError(f"JWT verification failed: {java_msg}")
        elif "INVALID_KEY" in java_msg:
            return RuntimeError(f"Key error: {java_msg}")
        else:
            return RuntimeError(f"JWT error: {java_msg}")


def get_instance():
    """Return the singleton SecurityBridge instance."""
    return SecurityBridge()
