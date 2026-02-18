package com.securitybridge;

import java.util.Collection;
import java.util.regex.Pattern;
import java.util.logging.Logger;

/**
 * Static utility methods for input validation and sanitization.
 *
 * <p>Every method either returns the validated input unchanged or throws
 * {@link IllegalArgumentException}. This makes them safe to chain:</p>
 *
 * <pre>{@code
 * String name = ValidationUtils.requireAlphanumeric(
 *                   ValidationUtils.requireNonEmpty(input, "name"), "name");
 * }</pre>
 *
 * <h3>String Length Safety</h3>
 * All string-accepting methods enforce {@link #MAX_INPUT_LENGTH} (10,000 chars)
 * before any regex evaluation to prevent catastrophic backtracking or memory
 * pressure from oversized input.
 *
 * <h3>Pattern Definitions</h3>
 * <ul>
 *   <li><strong>Alphanumeric</strong> — {@code [a-zA-Z0-9_]} (letters, digits,
 *       and underscore). The underscore is included deliberately as it is safe
 *       in identifiers, filenames, and database columns.</li>
 *   <li><strong>Path-safe</strong> — {@code [a-zA-Z0-9_./\-]} with an explicit
 *       block on {@code ..} directory traversal sequences.</li>
 * </ul>
 */
public final class ValidationUtils {

    private static final Logger LOGGER = Logger.getLogger(ValidationUtils.class.getName());

    // --- Constants -----------------------------------------------------------

    /**
     * Maximum allowed input string length. Applied before regex evaluation
     * to guard against catastrophic backtracking and memory exhaustion.
     */
    public static final int MAX_INPUT_LENGTH = 10_000;

    /**
     * Alphanumeric pattern: letters, digits, and underscore.
     * Underscore is intentionally included — safe for identifiers and filenames.
     */
    private static final Pattern ALPHANUMERIC_PATTERN = Pattern.compile("^[a-zA-Z0-9_]*$");

    /**
     * Path-safe pattern: letters, digits, underscore, dot, forward slash, hyphen.
     * Directory traversal ({@code ..}) is checked separately before this regex.
     */
    private static final Pattern PATH_SAFE_PATTERN = Pattern.compile("^[a-zA-Z0-9_./\\-]*$");

    // --- Construction --------------------------------------------------------

    /** Utility class — not instantiable. */
    private ValidationUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    // =========================================================================
    //  Null & Empty Checks
    // =========================================================================

    /**
     * Validates that an object reference is not null.
     *
     * @param obj       the object to validate
     * @param paramName parameter name for the error message
     * @param <T>       object type
     * @return the validated (non-null) object
     * @throws IllegalArgumentException if {@code obj} is null
     */
    public static <T> T requireNonNull(T obj, String paramName) {
        if (obj == null) {
            throw new IllegalArgumentException(paramName + " cannot be null");
        }
        return obj;
    }

    /**
     * Validates that a string is not null, not empty, and not blank.
     *
     * @param input     the string to validate
     * @param paramName parameter name for the error message
     * @return the validated string (unchanged)
     * @throws IllegalArgumentException if null, empty, or blank
     */
    public static String requireNonEmpty(String input, String paramName) {
        if (input == null || input.trim().isEmpty()) {
            throw new IllegalArgumentException(paramName + " cannot be null or empty");
        }
        enforceMaxLength(input, paramName);
        return input;
    }

    /**
     * Validates that a collection is not null or empty.
     *
     * @param collection the collection to validate
     * @param paramName  parameter name for the error message
     * @param <T>        element type
     * @return the validated collection (unchanged)
     * @throws IllegalArgumentException if null or empty
     */
    public static <T> Collection<T> requireNonEmpty(Collection<T> collection, String paramName) {
        if (collection == null || collection.isEmpty()) {
            throw new IllegalArgumentException(paramName + " cannot be null or empty");
        }
        return collection;
    }

    // =========================================================================
    //  String Format Validation
    // =========================================================================

    /**
     * Validates that a string contains only alphanumeric characters and
     * underscores ({@code [a-zA-Z0-9_]}).
     *
     * <p>Enforces {@link #MAX_INPUT_LENGTH} before regex evaluation.</p>
     *
     * @param input     the string to validate
     * @param paramName parameter name for the error message
     * @return the validated string (unchanged)
     * @throws IllegalArgumentException if null, empty, too long, or contains
     *         characters outside the allowed set
     */
    public static String requireAlphanumeric(String input, String paramName) {
        requireNonEmpty(input, paramName);

        if (!ALPHANUMERIC_PATTERN.matcher(input).matches()) {
            LOGGER.warning("Alphanumeric validation failed for param: " + paramName);
            throw new IllegalArgumentException(
                    paramName + " must be alphanumeric (letters, digits, underscore only)");
        }
        return input;
    }

    /**
     * Validates that a string is safe for use in file paths.
     *
     * <p>Blocks {@code ..} directory traversal sequences before applying
     * the path-safe regex. Enforces {@link #MAX_INPUT_LENGTH}.</p>
     *
     * @param input     the string to validate
     * @param paramName parameter name for the error message
     * @return the validated string (unchanged)
     * @throws IllegalArgumentException if null, empty, too long, contains
     *         traversal sequences, or has illegal path characters
     */
    public static String requirePathSafe(String input, String paramName) {
        requireNonEmpty(input, paramName);

        if (input.contains("..")) {
            throw new IllegalArgumentException(
                    paramName + " contains directory traversal sequence");
        }

        if (!PATH_SAFE_PATTERN.matcher(input).matches()) {
            throw new IllegalArgumentException(
                    paramName + " contains illegal characters for a file path");
        }
        return input;
    }

    // =========================================================================
    //  Numeric Range Validation
    // =========================================================================

    /**
     * Validates that an integer falls within an inclusive range.
     *
     * @param value     the value to validate
     * @param min       minimum allowed (inclusive)
     * @param max       maximum allowed (inclusive)
     * @param paramName parameter name for the error message
     * @return the validated value (unchanged)
     * @throws IllegalArgumentException if out of range
     */
    public static int requireRange(int value, int min, int max, String paramName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                    paramName + " must be between " + min + " and " + max
                    + " (got " + value + ")");
        }
        return value;
    }

    /**
     * Validates that a double falls within an inclusive range.
     *
     * @param value     the value to validate
     * @param min       minimum allowed (inclusive)
     * @param max       maximum allowed (inclusive)
     * @param paramName parameter name for the error message
     * @return the validated value (unchanged)
     * @throws IllegalArgumentException if out of range
     */
    public static double requireRange(double value, double min, double max, String paramName) {
        if (value < min || value > max) {
            throw new IllegalArgumentException(
                    paramName + " must be between " + min + " and " + max
                    + " (got " + value + ")");
        }
        return value;
    }

    // =========================================================================
    //  Soft Validation
    // =========================================================================

    /**
     * Logs a validation failure without throwing an exception.
     *
     * <p>Useful for non-critical or advisory checks where processing
     * should continue.</p>
     *
     * @param condition the condition to check
     * @param message   message to log if the condition is false
     * @return {@code true} if the condition holds, {@code false} otherwise
     */
    public static boolean softValidate(boolean condition, String message) {
        if (!condition) {
            LOGGER.warning("Soft validation failed: " + message);
        }
        return condition;
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    /**
     * Enforces {@link #MAX_INPUT_LENGTH} on a string.
     *
     * @param input     the string to check
     * @param paramName parameter name for the error message
     * @throws IllegalArgumentException if the string exceeds the limit
     */
    private static void enforceMaxLength(String input, String paramName) {
        if (input.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException(
                    paramName + " exceeds maximum length of " + MAX_INPUT_LENGTH
                    + " characters (got " + input.length() + ")");
        }
    }
}
