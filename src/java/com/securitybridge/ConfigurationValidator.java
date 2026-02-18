package com.securitybridge;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.Collections;
import java.util.regex.Pattern;
import java.util.logging.Logger;

/**
 * Validates configuration maps against security constraints.
 *
 * <p>Enforces required keys, numeric value ranges, and string sanitization
 * for arbitrary configuration types. Consumers register their own constraints
 * via {@link #addRequiredKeys} and {@link #addValueRange}; no domain-specific
 * defaults are assumed.</p>
 *
 * <h3>Input Safety</h3>
 * {@link #validateConfig} never mutates the input map. It returns a
 * defensive copy with sanitized string values.
 *
 * <h3>String Sanitization</h3>
 * Uses an allowlist pattern ({@link #SAFE_VALUE_PATTERN}) rather than a
 * blocklist. Only alphanumeric characters, spaces, hyphens, underscores,
 * dots, commas, colons, forward slashes, and {@code @} are permitted.
 * Characters outside the allowlist are stripped.
 *
 * <h3>Usage Example</h3>
 * <pre>{@code
 * ConfigurationValidator validator = new ConfigurationValidator();
 *
 * // Register constraints for "database" config type
 * validator.addRequiredKeys("database", Set.of("host", "port"));
 * validator.addValueRange("database", "port", 1, 65535);
 * validator.addValueRange("database", "pool_size", 1, 100);
 *
 * // Validate - returns a sanitized copy
 * Map<String, Object> clean = validator.validateConfig("database", rawConfig);
 * }</pre>
 */
public class ConfigurationValidator {

    private static final Logger LOGGER = Logger.getLogger(ConfigurationValidator.class.getName());

    /**
     * Allowlist pattern for safe configuration string values.
     * Permits: alphanumeric, space, hyphen, underscore, dot, comma, colon,
     * forward slash, and {@code @}.
     */
    private static final Pattern SAFE_VALUE_PATTERN = Pattern.compile("[^a-zA-Z0-9 \\-_.,/:@]");

    /** Maximum allowed length for any single string value. */
    private static final int MAX_STRING_LENGTH = 10_000;

    // Constraint registries (configType -> constraints)
    private final Map<String, Set<String>> requiredKeysMap;
    private final Map<String, Map<String, ValueRange>> valueRangesMap;

    /**
     * Creates a new ConfigurationValidator with no default constraints.
     * Register constraints via {@link #addRequiredKeys} and {@link #addValueRange}.
     */
    public ConfigurationValidator() {
        this.requiredKeysMap = new HashMap<>();
        this.valueRangesMap = new HashMap<>();
    }

    // =========================================================================
    //  Validation
    // =========================================================================

    /**
     * Validates a configuration map and returns a sanitized copy.
     *
     * <p>Performs three checks in order:</p>
     * <ol>
     *   <li><strong>Required keys</strong> — throws if any registered required
     *       key is missing from the config.</li>
     *   <li><strong>Value ranges</strong> — throws if any numeric value falls
     *       outside its registered min/max bounds.</li>
     *   <li><strong>String sanitization</strong> — strips characters outside the
     *       {@link #SAFE_VALUE_PATTERN} allowlist and enforces
     *       {@link #MAX_STRING_LENGTH}.</li>
     * </ol>
     *
     * <p>The input map is never modified. A defensive copy is returned.</p>
     *
     * @param configType non-empty configuration type identifier
     * @param config     non-null configuration map to validate
     * @return a new map containing validated and sanitized entries
     * @throws IllegalArgumentException if required keys are missing or values
     *         are out of range
     */
    public Map<String, Object> validateConfig(String configType, Map<String, Object> config) {
        ValidationUtils.requireNonEmpty(configType, "configType");
        ValidationUtils.requireNonNull(config, "config");

        // Work on a defensive copy — never mutate the caller's map
        Map<String, Object> result = new HashMap<>(config);

        checkRequiredKeys(configType, result);
        checkValueRanges(configType, result);
        sanitizeStrings(result);

        return result;
    }

    // =========================================================================
    //  Constraint Registration
    // =========================================================================

    /**
     * Registers required keys for a configuration type.
     *
     * <p>Replaces any previously registered required keys for this type.</p>
     *
     * @param configType   non-empty configuration type identifier
     * @param requiredKeys non-null set of required key names
     */
    public void addRequiredKeys(String configType, Set<String> requiredKeys) {
        ValidationUtils.requireNonEmpty(configType, "configType");
        ValidationUtils.requireNonNull(requiredKeys, "requiredKeys");

        this.requiredKeysMap.put(configType, new HashSet<>(requiredKeys));
    }

    /**
     * Registers a numeric value range for a specific key within a config type.
     *
     * @param configType non-empty configuration type identifier
     * @param key        non-empty configuration key name
     * @param min        minimum allowed value (inclusive)
     * @param max        maximum allowed value (inclusive)
     * @throws IllegalArgumentException if min &gt; max
     */
    public void addValueRange(String configType, String key, double min, double max) {
        ValidationUtils.requireNonEmpty(configType, "configType");
        ValidationUtils.requireNonEmpty(key, "key");

        if (min > max) {
            throw new IllegalArgumentException(
                    "min (" + min + ") must not exceed max (" + max + ")");
        }

        Map<String, ValueRange> ranges = valueRangesMap.computeIfAbsent(
                configType, k -> new HashMap<>());
        ranges.put(key, new ValueRange(min, max));
    }

    /**
     * Returns an unmodifiable view of the required keys for a config type,
     * or an empty set if none are registered.
     *
     * @param configType the configuration type
     * @return unmodifiable set of required key names
     */
    public Set<String> getRequiredKeys(String configType) {
        return Collections.unmodifiableSet(
                requiredKeysMap.getOrDefault(configType, Collections.emptySet()));
    }

    // =========================================================================
    //  Internal Validation Steps
    // =========================================================================

    private void checkRequiredKeys(String configType, Map<String, Object> config) {
        Set<String> required = requiredKeysMap.getOrDefault(configType, Collections.emptySet());
        for (String key : required) {
            if (!config.containsKey(key)) {
                throw new IllegalArgumentException(
                        "Required configuration key missing for type '"
                        + configType + "': " + key);
            }
        }
    }

    private void checkValueRanges(String configType, Map<String, Object> config) {
        Map<String, ValueRange> ranges = valueRangesMap.getOrDefault(
                configType, Collections.emptyMap());

        for (Map.Entry<String, ValueRange> entry : ranges.entrySet()) {
            String key = entry.getKey();
            ValueRange range = entry.getValue();

            if (config.containsKey(key) && config.get(key) instanceof Number) {
                double value = ((Number) config.get(key)).doubleValue();
                if (value < range.min || value > range.max) {
                    throw new IllegalArgumentException(
                            "Configuration value for '" + key + "' is " + value
                            + " but must be between " + range.min
                            + " and " + range.max);
                }
            }
        }
    }

    private void sanitizeStrings(Map<String, Object> config) {
        for (Map.Entry<String, Object> entry : config.entrySet()) {
            if (entry.getValue() instanceof String) {
                String raw = (String) entry.getValue();

                // Enforce maximum length
                if (raw.length() > MAX_STRING_LENGTH) {
                    LOGGER.warning("Configuration value for '" + entry.getKey()
                            + "' exceeds max length (" + MAX_STRING_LENGTH
                            + "), truncating");
                    raw = raw.substring(0, MAX_STRING_LENGTH);
                }

                // Allowlist sanitization — strip anything not in SAFE_VALUE_PATTERN
                String sanitized = SAFE_VALUE_PATTERN.matcher(raw).replaceAll("");

                if (!sanitized.equals(entry.getValue())) {
                    LOGGER.warning("Sanitized unsafe characters in configuration key: "
                            + entry.getKey());
                }

                entry.setValue(sanitized);
            }
        }
    }

    // =========================================================================
    //  Value Range Record
    // =========================================================================

    /**
     * Represents an inclusive numeric range [min, max].
     */
    private static class ValueRange {
        final double min;
        final double max;

        ValueRange(double min, double max) {
            this.min = min;
            this.max = max;
        }
    }
}
