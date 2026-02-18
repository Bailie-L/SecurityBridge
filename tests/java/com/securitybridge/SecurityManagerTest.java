package com.securitybridge;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;

/**
 * Unit tests for SecurityManager.
 */
public class SecurityManagerTest {

    private static final String AUTH_TOKEN = System.getenv("SECURITYBRIDGE_AUTH_TOKEN");

    private SecurityManager securityManager;

    @BeforeEach
    public void setUp() {
        SecurityManager.resetForTesting();
        securityManager = SecurityManager.getInstance();
        securityManager.setSecurityEnabled(true, AUTH_TOKEN);
    }

    @AfterEach
    public void tearDown() {
        // Always re-enable security after each test
        try {
            securityManager.setSecurityEnabled(true, AUTH_TOKEN);
        } catch (Exception ignored) {
        }
    }

    // =========================================================================
    //  Singleton
    // =========================================================================

    @Test
    @DisplayName("getInstance should return the same instance (singleton)")
    public void testGetInstanceReturnsSameInstance() {
        SecurityManager instance1 = SecurityManager.getInstance();
        SecurityManager instance2 = SecurityManager.getInstance();

        assertNotNull(instance1);
        assertSame(instance1, instance2);
    }

    @Test
    @DisplayName("resetForTesting should create a fresh instance")
    public void testResetForTesting() {
        SecurityManager before = SecurityManager.getInstance();
        SecurityManager.resetForTesting();
        SecurityManager after = SecurityManager.getInstance();

        assertNotSame(before, after);
    }

    // =========================================================================
    //  String Validation
    // =========================================================================

    @Test
    @DisplayName("validateString alphanumeric should pass valid input")
    public void testValidateStringWithValidAlphanumeric() {
        assertEquals("valid123_string",
                securityManager.validateString("valid123_string", "testParam", "alphanumeric"));
    }

    @Test
    @DisplayName("validateString alphanumeric should reject invalid input")
    public void testValidateStringWithInvalidAlphanumeric() {
        assertTrue(securityManager.isSecurityEnabled());

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                securityManager.validateString("invalid-string!", "testParam", "alphanumeric"));

        assertTrue(ex.getMessage().contains("must be alphanumeric"));
    }

    @Test
    @DisplayName("validateString path should pass valid paths")
    public void testValidateStringWithValidPath() {
        assertEquals("valid/path/to/file.txt",
                securityManager.validateString("valid/path/to/file.txt", "testParam", "path"));
    }

    @Test
    @DisplayName("validateString path should reject invalid paths")
    public void testValidateStringWithInvalidPath() {
        assertTrue(securityManager.isSecurityEnabled());

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                securityManager.validateString("invalid<path>/file.txt", "testParam", "path"));

        assertTrue(ex.getMessage().contains("illegal characters for a file path"));
    }

    @Test
    @DisplayName("validateString default should pass non-empty strings")
    public void testValidateStringDefault() {
        assertEquals("hello",
                securityManager.validateString("hello", "testParam", "default"));
    }

    // =========================================================================
    //  Range Validation
    // =========================================================================

    @Test
    @DisplayName("validateRange should pass values within range")
    public void testValidateRangeWithValidValue() {
        assertEquals(5, securityManager.validateRange(5, 1, 10, "testParam"));
    }

    @Test
    @DisplayName("validateRange should reject values outside range")
    public void testValidateRangeWithInvalidValue() {
        assertTrue(securityManager.isSecurityEnabled());

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                securityManager.validateRange(20, 1, 10, "testParam"));

        assertTrue(ex.getMessage().contains("must be between 1 and 10"));
    }

    // =========================================================================
    //  Configuration Validation
    // =========================================================================

    @Test
    @DisplayName("validateConfiguration should pass valid configs")
    public void testValidateConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("key1", "value1");
        config.put("key2", 123);

        Map<String, Object> result = securityManager.validateConfiguration("test_type", config);

        assertNotNull(result);
        assertEquals("value1", result.get("key1"));
        assertEquals(123, result.get("key2"));
    }

    @Test
    @DisplayName("getConfigValidator should return non-null validator")
    public void testGetConfigValidator() {
        assertNotNull(securityManager.getConfigValidator());
    }

    // =========================================================================
    //  Security Toggle
    // =========================================================================

    @Test
    @DisplayName("setSecurityEnabled should toggle validation on and off")
    public void testSetSecurityEnabled() {
        // Disable — invalid input should pass through
        securityManager.setSecurityEnabled(false, AUTH_TOKEN);
        assertFalse(securityManager.isSecurityEnabled());

        String invalidInput = "invalid<path>";
        assertEquals(invalidInput,
                securityManager.validateString(invalidInput, "testParam", "path"),
                "Validation should be bypassed when disabled");

        // Re-enable — same input should now fail
        securityManager.setSecurityEnabled(true, AUTH_TOKEN);
        assertTrue(securityManager.isSecurityEnabled());

        assertThrows(IllegalArgumentException.class, () ->
                securityManager.validateString(invalidInput, "testParam", "path"));
    }

    @Test
    @DisplayName("Disabled security should bypass range validation")
    public void testDisabledSecurityBypassesRange() {
        securityManager.setSecurityEnabled(false, AUTH_TOKEN);

        // Out-of-range value should pass through
        assertEquals(999, securityManager.validateRange(999, 1, 10, "testParam"));
    }

    @Test
    @DisplayName("Disabled security should bypass configuration validation")
    public void testDisabledSecurityBypassesConfig() {
        securityManager.setSecurityEnabled(false, AUTH_TOKEN);

        Map<String, Object> config = new HashMap<>();
        config.put("anything", "goes");

        Map<String, Object> result = securityManager.validateConfiguration("strict_type", config);
        assertSame(config, result, "Should return input map directly when disabled");
    }

    @Test
    @DisplayName("setSecurityEnabled should reject invalid auth token")
    public void testSetSecurityEnabledRejectsInvalidToken() {
        assertThrows(SecurityException.class, () ->
                securityManager.setSecurityEnabled(false, "wrong-token"));

        // Security should still be enabled
        assertTrue(securityManager.isSecurityEnabled());
    }

    @Test
    @DisplayName("setSecurityEnabled should reject null auth token")
    public void testSetSecurityEnabledRejectsNullToken() {
        assertThrows(SecurityException.class, () ->
                securityManager.setSecurityEnabled(false, null));
    }

    // =========================================================================
    //  Security Metrics & Events
    // =========================================================================

    @Test
    @DisplayName("recordSecurityEvent should track event count and timestamp")
    public void testRecordSecurityEvent() {
        securityManager.recordSecurityEvent("test_event", "Test details", Level.WARNING);

        Map<String, Object> metrics = securityManager.getSecurityMetrics();
        assertNotNull(metrics);

        String counterKey = "count.test_event";
        assertTrue(metrics.containsKey(counterKey));
        assertEquals(1, metrics.get(counterKey));

        String timestampKey = "lastOccurrence.test_event";
        assertTrue(metrics.containsKey(timestampKey));
        assertTrue(metrics.get(timestampKey) instanceof Long);
    }

    @Test
    @DisplayName("recordSecurityEvent should increment counter on repeated events")
    public void testRecordSecurityEventIncrementsCounter() {
        securityManager.recordSecurityEvent("repeat", "first", Level.INFO);
        securityManager.recordSecurityEvent("repeat", "second", Level.INFO);
        securityManager.recordSecurityEvent("repeat", "third", Level.INFO);

        Map<String, Object> metrics = securityManager.getSecurityMetrics();
        assertEquals(3, metrics.get("count.repeat"));
    }

    @Test
    @DisplayName("addSecurityMetric should store and retrieve metrics")
    public void testAddSecurityMetric() {
        securityManager.addSecurityMetric("test_metric", "test_value");

        Map<String, Object> metrics = securityManager.getSecurityMetrics();
        assertEquals("test_value", metrics.get("test_metric"));
    }

    @Test
    @DisplayName("getSecurityMetrics should return a defensive copy")
    public void testGetSecurityMetricsReturnsDefensiveCopy() {
        securityManager.addSecurityMetric("key", "value");

        Map<String, Object> copy = securityManager.getSecurityMetrics();
        copy.put("injected", "bad");

        // Original should be unaffected
        assertFalse(securityManager.getSecurityMetrics().containsKey("injected"));
    }
}
