package com.securitybridge;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Unit tests for ConfigurationValidator.
 */
public class ConfigurationValidatorTest {

    private ConfigurationValidator validator;

    @BeforeEach
    public void setUp() {
        validator = new ConfigurationValidator();

        // Register test constraints
        validator.addRequiredKeys("test_config", Set.of("required_key1", "required_key2"));
        validator.addValueRange("test_config", "numeric_value", 1.0, 100.0);
    }

    // =========================================================================
    //  Valid Configuration
    // =========================================================================

    @Test
    @DisplayName("validateConfig should accept valid configurations")
    public void testValidateConfigWithValidConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "value1");
        config.put("required_key2", "value2");
        config.put("numeric_value", 50);
        config.put("optional_key", "optional_value");

        Map<String, Object> result = validator.validateConfig("test_config", config);

        assertNotNull(result);
        assertEquals(config.size(), result.size());
        assertEquals("value1", result.get("required_key1"));
        assertEquals("value2", result.get("required_key2"));
        assertEquals(50, result.get("numeric_value"));
    }

    @Test
    @DisplayName("validateConfig should accept configurations for unknown config types")
    public void testValidateConfigWithUnknownConfigType() {
        Map<String, Object> config = Map.of("key1", "value1", "key2", "value2");

        Map<String, Object> result = validator.validateConfig("unknown_type", config);

        assertNotNull(result);
        assertEquals(2, result.size());
    }

    // =========================================================================
    //  Required Keys
    // =========================================================================

    @Test
    @DisplayName("validateConfig should throw for missing required keys")
    public void testValidateConfigWithMissingRequiredKey() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "value1");
        // Missing required_key2

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("test_config", config));

        assertTrue(ex.getMessage().contains("Required configuration key missing"));
    }

    @Test
    @DisplayName("addRequiredKeys should register keys for new config types")
    public void testAddRequiredKeys() {
        validator.addRequiredKeys("new_type", Set.of("must_have"));

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("new_type", new HashMap<>()));

        assertTrue(ex.getMessage().contains("must_have"));
    }

    @Test
    @DisplayName("getRequiredKeys should return registered keys")
    public void testGetRequiredKeys() {
        Set<String> keys = validator.getRequiredKeys("test_config");

        assertTrue(keys.contains("required_key1"));
        assertTrue(keys.contains("required_key2"));
        assertEquals(2, keys.size());
    }

    @Test
    @DisplayName("getRequiredKeys should return empty set for unknown types")
    public void testGetRequiredKeysUnknownType() {
        Set<String> keys = validator.getRequiredKeys("nonexistent");

        assertNotNull(keys);
        assertTrue(keys.isEmpty());
    }

    // =========================================================================
    //  Value Ranges
    // =========================================================================

    @Test
    @DisplayName("validateConfig should throw for out-of-range numeric values")
    public void testValidateConfigWithOutOfRangeNumericValue() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "value1");
        config.put("required_key2", "value2");
        config.put("numeric_value", 150);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("test_config", config));

        assertTrue(ex.getMessage().contains("must be between 1.0 and 100.0"));
    }

    @Test
    @DisplayName("addValueRange should register range for new config types")
    public void testAddValueRange() {
        validator.addValueRange("range_type", "port", 1, 65535);

        Map<String, Object> config = Map.of("port", 0);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("range_type", config));

        assertTrue(ex.getMessage().contains("must be between"));
    }

    @Test
    @DisplayName("addValueRange should throw when min exceeds max")
    public void testAddValueRangeMinExceedsMax() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.addValueRange("bad", "key", 100, 1));

        assertTrue(ex.getMessage().contains("must not exceed max"));
    }

    // =========================================================================
    //  String Sanitization (Allowlist)
    // =========================================================================

    @Test
    @DisplayName("validateConfig should strip characters outside the allowlist")
    public void testValidateConfigSanitizesStrings() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "value1");
        config.put("required_key2", "value2");
        config.put("command", "echo hello; rm -rf /");

        Map<String, Object> result = validator.validateConfig("test_config", config);

        assertNotNull(result);
        String sanitized = (String) result.get("command");
        // Semicolon is not in the allowlist — must be stripped
        assertFalse(sanitized.contains(";"), "Semicolon should be stripped");
        // Alphanumeric, spaces, hyphens, and forward slash ARE in the allowlist
        assertTrue(sanitized.contains("echo hello"), "Safe text should survive");
        assertTrue(sanitized.contains("rm -rf /"), "Hyphens and slashes should survive");
    }

    @Test
    @DisplayName("validateConfig should strip shell metacharacters")
    public void testValidateConfigStripsShellMetachars() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "safe");
        config.put("required_key2", "safe");
        config.put("input", "$(whoami) && cat /etc/passwd | grep root");

        Map<String, Object> result = validator.validateConfig("test_config", config);

        String sanitized = (String) result.get("input");
        assertFalse(sanitized.contains("$"), "Dollar should be stripped");
        assertFalse(sanitized.contains("("), "Paren should be stripped");
        assertFalse(sanitized.contains(")"), "Paren should be stripped");
        assertFalse(sanitized.contains("&"), "Ampersand should be stripped");
        assertFalse(sanitized.contains("|"), "Pipe should be stripped");
        // Safe characters survive
        assertTrue(sanitized.contains("whoami"));
        assertTrue(sanitized.contains("cat /etc/passwd"));
        assertTrue(sanitized.contains("grep root"));
    }

    @Test
    @DisplayName("validateConfig should allow safe characters through allowlist")
    public void testValidateConfigAllowsSafeChars() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "ok");
        config.put("required_key2", "ok");
        config.put("url", "https://example.com:8080/api/v1");
        config.put("email", "user@example.com");

        Map<String, Object> result = validator.validateConfig("test_config", config);

        // Colon, forward slash, dot, hyphen, @ are all in the allowlist
        assertEquals("https://example.com:8080/api/v1", result.get("url"));
        assertEquals("user@example.com", result.get("email"));
    }

    // =========================================================================
    //  Input Non-Mutation
    // =========================================================================

    @Test
    @DisplayName("validateConfig should not mutate the input map")
    public void testValidateConfigDoesNotMutateInput() {
        Map<String, Object> config = new HashMap<>();
        config.put("required_key1", "value1");
        config.put("required_key2", "value2");
        config.put("dirty", "hello; world");

        // Keep a copy of the original value
        String originalDirty = (String) config.get("dirty");

        Map<String, Object> result = validator.validateConfig("test_config", config);

        // Input map must be untouched
        assertEquals(originalDirty, config.get("dirty"),
                "Input map should not be mutated by validateConfig");

        // Result should be sanitized
        assertFalse(((String) result.get("dirty")).contains(";"));

        // Result must be a different map instance
        assertNotSame(config, result);
    }

    // =========================================================================
    //  Null / Empty Guards
    // =========================================================================

    @Test
    @DisplayName("validateConfig should throw for null config")
    public void testValidateConfigWithNullConfig() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("test_config", null));

        assertTrue(ex.getMessage().contains("cannot be null"));
    }

    @Test
    @DisplayName("validateConfig should throw for null config type")
    public void testValidateConfigWithNullConfigType() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig(null, new HashMap<>()));

        assertTrue(ex.getMessage().contains("cannot be null or empty"));
    }

    @Test
    @DisplayName("validateConfig should throw for empty config type")
    public void testValidateConfigWithEmptyConfigType() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                validator.validateConfig("", new HashMap<>()));

        assertTrue(ex.getMessage().contains("cannot be null or empty"));
    }
}
