package com.securitybridge;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * Central coordinator for the SecurityBridge framework.
 *
 * <p>Delegates to specialist classes for specific operations:</p>
 * <ul>
 *   <li>{@link ValidationUtils} — string and numeric input validation</li>
 *   <li>{@link ConfigurationValidator} — configuration map validation</li>
 *   <li>{@link RateLimiter} — per-client rate limiting</li>
 * </ul>
 *
 * <h3>Singleton</h3>
 * A single JVM-wide instance is shared across all threads. The metrics map
 * is wrapped via {@link Collections#synchronizedMap} for thread safety.
 *
 * <h3>Security Toggle</h3>
 * Validation can be disabled via {@link #setSecurityEnabled(boolean, String)},
 * which requires the {@code SECURITYBRIDGE_AUTH_TOKEN} environment variable
 * to match the supplied token. When disabled, validation methods return
 * input unchanged (documented pass-through behaviour).
 *
 * <h3>Usage Example</h3>
 * <pre>{@code
 * SecurityManager sm = SecurityManager.getInstance();
 *
 * // Validate user input
 * String clean = sm.validateString(userInput, "username", "alphanumeric");
 *
 * // Validate a configuration map
 * Map<String, Object> cfg = sm.validateConfiguration("database", rawConfig);
 *
 * // Record a security event
 * sm.recordSecurityEvent("auth_failure", "Bad password for user X", Level.WARNING);
 * }</pre>
 */
public class SecurityManager {

    private static final Logger LOGGER = Logger.getLogger(SecurityManager.class.getName());

    private static volatile SecurityManager instance;

    /** Maximum tracked metric keys (LRU eviction beyond this). */
    private static final int MAX_METRICS_ENTRIES = 5_000;

    private final ConfigurationValidator configValidator;
    private final JwtValidator jwtValidator;
    private final HtmlSanitizer htmlSanitizer;
    private final Map<String, Object> securityMetrics;
    private final AtomicBoolean securityEnabled;

    // =========================================================================
    //  Construction & Singleton
    // =========================================================================

    /**
     * Private constructor — use {@link #getInstance()}.
     */
    private SecurityManager() {
        this.configValidator = new ConfigurationValidator();
        this.jwtValidator = new JwtValidator();
        this.htmlSanitizer = new HtmlSanitizer();
        this.securityMetrics = Collections.synchronizedMap(boundedLruMap(MAX_METRICS_ENTRIES));
        this.securityEnabled = new AtomicBoolean(true);
        LOGGER.info("SecurityManager initialized");
    }

    /**
     * Returns the singleton instance (double-checked locking).
     *
     * @return the SecurityManager singleton
     */
    public static SecurityManager getInstance() {
        if (instance == null) {
            synchronized (SecurityManager.class) {
                if (instance == null) {
                    instance = new SecurityManager();
                }
            }
        }
        return instance;
    }

    /**
     * Resets the singleton instance. <strong>Testing only.</strong>
     */
    public static synchronized void resetForTesting() {
        instance = null;
    }

    // =========================================================================
    //  String Validation
    // =========================================================================

    /**
     * Validates a string input against the specified validation type.
     *
     * <p>Supported types:</p>
     * <ul>
     *   <li>{@code "alphanumeric"} — letters, digits, and underscores only</li>
     *   <li>{@code "path"} — filesystem-safe characters, no traversal</li>
     *   <li>anything else — non-empty check only</li>
     * </ul>
     *
     * <p>When security is disabled, returns {@code input} unchanged.</p>
     *
     * @param input          the string to validate
     * @param paramName      parameter name for error messages
     * @param validationType the type of validation to apply
     * @return the validated string
     * @throws IllegalArgumentException if validation fails
     */
    public String validateString(String input, String paramName, String validationType) {
        if (!securityEnabled.get()) {
            LOGGER.fine("String validation bypassed (disabled): " + paramName);
            return input;
        }

        if ("alphanumeric".equalsIgnoreCase(validationType)) {
            return ValidationUtils.requireAlphanumeric(input, paramName);
        } else if ("path".equalsIgnoreCase(validationType)) {
            return ValidationUtils.requirePathSafe(input, paramName);
        } else {
            return ValidationUtils.requireNonEmpty(input, paramName);
        }
    }

    // =========================================================================
    /**
     * Validates a JWT token and returns the parsed claims.
     *
     * <p>When security is disabled, throws {@link IllegalStateException}
     * rather than returning unvalidated claims (tokens must always be verified).</p>
     *
     * @param token  the compact JWT string
     * @param secret the HMAC shared secret
     * @return parsed claims as a map
     * @throws JwtValidator.JwtValidationException if validation fails
     * @throws IllegalStateException if security is disabled
     */
    public Map<String, Object> validateJwt(String token, String secret) {
        if (!securityEnabled.get()) {
            throw new IllegalStateException("Cannot validate JWT: security is disabled");
        }
        return jwtValidator.validateHmac(token, secret);
    }

    /**
     * Validates a JWT with issuer and audience constraints.
     *
     * @param token            the compact JWT string
     * @param secret           the HMAC shared secret
     * @param expectedIssuer   required issuer, or null to skip
     * @param expectedAudience required audience, or null to skip
     * @return parsed claims as a map
     * @throws JwtValidator.JwtValidationException if validation fails
     * @throws IllegalStateException if security is disabled
     */
    public Map<String, Object> validateJwt(String token, String secret,
                                           String expectedIssuer, String expectedAudience) {
        if (!securityEnabled.get()) {
            throw new IllegalStateException("Cannot validate JWT: security is disabled");
        }
        return jwtValidator.validateHmac(token, secret, expectedIssuer, expectedAudience);
    }

    /**
     * Validates a JWT signed with RSA.
     *
     * @param token        the compact JWT string
     * @param publicKeyPem the RSA public key in PEM format
     * @return parsed claims as a map
     * @throws JwtValidator.JwtValidationException if validation fails
     * @throws IllegalStateException if security is disabled
     */
    public Map<String, Object> validateJwtRsa(String token, String publicKeyPem) {
        if (!securityEnabled.get()) {
            throw new IllegalStateException("Cannot validate JWT: security is disabled");
        }
        return jwtValidator.validateRsa(token, publicKeyPem);
    }

    /**
     * Sanitizes HTML input using the named policy.
     *
     * <p>When security is disabled, returns input unchanged.</p>
     *
     * @param html       the untrusted HTML string
     * @param policyName one of STRICT, BASIC, RICH, or a custom policy
     * @return the sanitized HTML
     */
    public String sanitizeHtml(String html, String policyName) {
        if (!securityEnabled.get()) {
            LOGGER.fine("HTML sanitization bypassed (disabled)");
            return html;
        }
        return htmlSanitizer.sanitize(html, policyName);
    }

    /**
     * Sanitizes HTML and returns an audit report of stripped content.
     *
     * @param html       the untrusted HTML string
     * @param policyName the policy to apply
     * @return sanitization result with audit data
     * @throws IllegalStateException if security is disabled
     */
    public HtmlSanitizer.SanitizationResult sanitizeHtmlWithReport(String html, String policyName) {
        if (!securityEnabled.get()) {
            throw new IllegalStateException("Cannot produce sanitization report: security is disabled");
        }
        return htmlSanitizer.sanitizeWithReport(html, policyName);
    }

    //  Numeric Validation
    // =========================================================================

    /**
     * Validates that a numeric value falls within an inclusive range.
     *
     * <p>When security is disabled, returns {@code value} unchanged.</p>
     *
     * @param value     the value to validate
     * @param min       minimum allowed (inclusive)
     * @param max       maximum allowed (inclusive)
     * @param paramName parameter name for error messages
     * @return the validated value
     * @throws IllegalArgumentException if out of range
     */
    public int validateRange(int value, int min, int max, String paramName) {
        if (!securityEnabled.get()) {
            LOGGER.fine("Range validation bypassed (disabled): " + paramName);
            return value;
        }

        return ValidationUtils.requireRange(value, min, max, paramName);
    }

    // =========================================================================
    //  Configuration Validation
    // =========================================================================

    /**
     * Validates a configuration map against registered constraints.
     *
     * <p>Delegates to {@link ConfigurationValidator#validateConfig}. When
     * security is disabled, returns the input map unchanged (no copy).</p>
     *
     * @param configType non-empty configuration type identifier
     * @param config     non-null configuration map
     * @return a validated, sanitized copy of the configuration
     * @throws IllegalArgumentException if validation fails
     */
    public Map<String, Object> validateConfiguration(String configType, Map<String, Object> config) {
        if (!securityEnabled.get()) {
            LOGGER.fine("Configuration validation bypassed (disabled)");
            return config;
        }

        LOGGER.fine("Validating configuration: " + configType);
        return configValidator.validateConfig(configType, config);
    }

    /**
     * Returns the underlying {@link ConfigurationValidator} for constraint
     * registration.
     *
     * @return the configuration validator
     */
    public ConfigurationValidator getConfigValidator() {
        return configValidator;
    }

    // =========================================================================
    //  Security Toggle
    // =========================================================================

    /**
     * Enables or disables all security validation.
     *
     * <p>Requires the {@code SECURITYBRIDGE_AUTH_TOKEN} environment variable
     * to be set and to match the supplied {@code authToken}.</p>
     *
     * @param enabled   {@code true} to enable, {@code false} to disable
     * @param authToken authorisation token (must match env var)
     * @throws SecurityException if the token is missing or does not match
     */
    public void setSecurityEnabled(boolean enabled, String authToken) {
        String expected = System.getenv("SECURITYBRIDGE_AUTH_TOKEN");
        if (expected == null || !expected.equals(authToken)) {
            LOGGER.warning("Unauthorised attempt to change security state");
            throw new SecurityException("Invalid authorisation token");
        }

        securityEnabled.set(enabled);
        LOGGER.info("Security validation " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Returns whether security validation is currently enabled.
     *
     * @return {@code true} if enabled
     */
    public boolean isSecurityEnabled() {
        return securityEnabled.get();
    }

    // =========================================================================
    //  Security Metrics & Events
    // =========================================================================

    /**
     * Records a security event, incrementing the event counter and storing
     * the last occurrence timestamp.
     *
     * <p>Metrics keys follow the convention:</p>
     * <ul>
     *   <li>{@code count.<eventType>} — cumulative event count</li>
     *   <li>{@code lastOccurrence.<eventType>} — epoch millis of last event</li>
     * </ul>
     *
     * @param eventType non-null event type identifier
     * @param details   human-readable event details
     * @param severity  log level for the event
     */
    public void recordSecurityEvent(String eventType, String details, Level severity) {
        LOGGER.log(severity, "Security Event [" + eventType + "]: " + details);

        synchronized (securityMetrics) {
            String counterKey = "count." + eventType;
            int current = 0;
            Object existing = securityMetrics.get(counterKey);
            if (existing instanceof Integer) {
                current = (Integer) existing;
            }
            securityMetrics.put(counterKey, current + 1);
            securityMetrics.put("lastOccurrence." + eventType, System.currentTimeMillis());
        }
    }

    /**
     * Stores a custom security metric.
     *
     * @param metricName non-null metric key
     * @param value      metric value
     */
    public void addSecurityMetric(String metricName, Object value) {
        securityMetrics.put(metricName, value);
    }

    /**
     * Returns a snapshot of all current security metrics.
     *
     * @return defensive copy of the metrics map
     */
    public Map<String, Object> getSecurityMetrics() {
        synchronized (securityMetrics) {
            return new HashMap<>(securityMetrics);
        }
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    /**
     * Creates a bounded LinkedHashMap with LRU eviction.
     */
    private static <K, V> LinkedHashMap<K, V> boundedLruMap(int maxEntries) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }
}
