package com.securitybridge;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Unit tests for ValidationUtils.
 */
public class ValidationUtilsTest {

    // =========================================================================
    //  requireNonEmpty (String)
    // =========================================================================

    @Test
    @DisplayName("requireNonEmpty should accept valid strings")
    public void testRequireNonEmptyWithValidString() {
        assertEquals("valid-input", ValidationUtils.requireNonEmpty("valid-input", "testParam"));
    }

    @Test
    @DisplayName("requireNonEmpty should throw for null strings")
    public void testRequireNonEmptyWithNull() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty((String) null, "testParam"));

        assertTrue(ex.getMessage().contains("testParam cannot be null"));
    }

    @Test
    @DisplayName("requireNonEmpty should throw for empty strings")
    public void testRequireNonEmptyWithEmptyString() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty("", "testParam"));

        assertTrue(ex.getMessage().contains("testParam cannot be null or empty"));
    }

    @Test
    @DisplayName("requireNonEmpty should throw for blank strings")
    public void testRequireNonEmptyWithBlankString() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty("   ", "testParam"));

        assertTrue(ex.getMessage().contains("testParam cannot be null or empty"));
    }

    // =========================================================================
    //  requireAlphanumeric
    // =========================================================================

    @Test
    @DisplayName("requireAlphanumeric should accept letters, digits, and underscores")
    public void testRequireAlphanumericWithValidString() {
        assertEquals("valid123_string", ValidationUtils.requireAlphanumeric("valid123_string", "testParam"));
    }

    @Test
    @DisplayName("requireAlphanumeric should accept underscores (intentional)")
    public void testRequireAlphanumericAllowsUnderscore() {
        assertEquals("with_underscore", ValidationUtils.requireAlphanumeric("with_underscore", "testParam"));
    }

    @Test
    @DisplayName("requireAlphanumeric should throw for non-alphanumeric strings")
    public void testRequireAlphanumericWithInvalidString() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireAlphanumeric("invalid-string!", "testParam"));

        assertTrue(ex.getMessage().contains("must be alphanumeric"));
    }

    @Test
    @DisplayName("requireAlphanumeric should throw for strings with spaces")
    public void testRequireAlphanumericWithSpaces() {
        assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireAlphanumeric("has space", "testParam"));
    }

    // =========================================================================
    //  requirePathSafe
    // =========================================================================

    @Test
    @DisplayName("requirePathSafe should accept valid path strings")
    public void testRequirePathSafeWithValidString() {
        assertEquals("valid/path/to/file.txt",
                ValidationUtils.requirePathSafe("valid/path/to/file.txt", "testParam"));
    }

    @Test
    @DisplayName("requirePathSafe should throw for invalid path characters")
    public void testRequirePathSafeWithInvalidString() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requirePathSafe("invalid<path>/file.txt", "testParam"));

        assertTrue(ex.getMessage().contains("illegal characters for a file path"));
    }

    @Test
    @DisplayName("requirePathSafe should block directory traversal with ../")
    public void testRequirePathSafeBlocksTraversalForward() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requirePathSafe("../etc/passwd", "path"));

        assertTrue(ex.getMessage().contains("directory traversal"));
    }

    @Test
    @DisplayName("requirePathSafe should block directory traversal with ..\\")
    public void testRequirePathSafeBlocksTraversalBackslash() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requirePathSafe("..\\windows\\system32", "path"));

        assertTrue(ex.getMessage().contains("directory traversal"));
    }

    @Test
    @DisplayName("requirePathSafe should block embedded traversal sequences")
    public void testRequirePathSafeBlocksEmbeddedTraversal() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requirePathSafe("safe/../../etc/passwd", "path"));

        assertTrue(ex.getMessage().contains("directory traversal"));
    }

    @Test
    @DisplayName("requirePathSafe should allow single dots in filenames")
    public void testRequirePathSafeAllowsSingleDot() {
        assertEquals("path/to/file.txt",
                ValidationUtils.requirePathSafe("path/to/file.txt", "testParam"));
    }

    // =========================================================================
    //  Max Input Length
    // =========================================================================

    @Test
    @DisplayName("requireNonEmpty should throw for strings exceeding MAX_INPUT_LENGTH")
    public void testRequireNonEmptyExceedsMaxLength() {
        String oversized = "a".repeat(ValidationUtils.MAX_INPUT_LENGTH + 1);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty(oversized, "testParam"));

        assertTrue(ex.getMessage().contains("exceeds maximum length"));
    }

    @Test
    @DisplayName("requireAlphanumeric should throw for strings exceeding MAX_INPUT_LENGTH")
    public void testRequireAlphanumericExceedsMaxLength() {
        String oversized = "a".repeat(ValidationUtils.MAX_INPUT_LENGTH + 1);

        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireAlphanumeric(oversized, "testParam"));

        assertTrue(ex.getMessage().contains("exceeds maximum length"));
    }

    @Test
    @DisplayName("Strings at exactly MAX_INPUT_LENGTH should be accepted")
    public void testRequireNonEmptyAtExactMaxLength() {
        String exact = "a".repeat(ValidationUtils.MAX_INPUT_LENGTH);

        assertEquals(exact, ValidationUtils.requireNonEmpty(exact, "testParam"));
    }

    // =========================================================================
    //  requireRange (int)
    // =========================================================================

    @Test
    @DisplayName("requireRange int should accept values within range")
    public void testRequireRangeIntWithValidValue() {
        assertEquals(5, ValidationUtils.requireRange(5, 1, 10, "testParam"));
    }

    @Test
    @DisplayName("requireRange int should throw for values outside range")
    public void testRequireRangeIntWithInvalidValue() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireRange(20, 1, 10, "testParam"));

        assertTrue(ex.getMessage().contains("must be between 1 and 10"));
    }

    @Test
    @DisplayName("requireRange int should accept boundary values")
    public void testRequireRangeIntBoundaryValues() {
        assertEquals(1, ValidationUtils.requireRange(1, 1, 10, "testParam"));
        assertEquals(10, ValidationUtils.requireRange(10, 1, 10, "testParam"));
    }

    // =========================================================================
    //  requireRange (double)
    // =========================================================================

    @Test
    @DisplayName("requireRange double should accept values within range")
    public void testRequireRangeDoubleWithValidValue() {
        assertEquals(5.5, ValidationUtils.requireRange(5.5, 1.0, 10.0, "testParam"));
    }

    @Test
    @DisplayName("requireRange double should throw for values outside range")
    public void testRequireRangeDoubleWithInvalidValue() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireRange(0.5, 1.0, 10.0, "testParam"));

        assertTrue(ex.getMessage().contains("must be between 1.0 and 10.0"));
    }

    // =========================================================================
    //  requireNonEmpty (Collection)
    // =========================================================================

    @Test
    @DisplayName("requireNonEmpty collection should accept non-empty collections")
    public void testRequireNonEmptyCollectionWithValidCollection() {
        List<String> input = Arrays.asList("item1", "item2");
        assertEquals(input, ValidationUtils.requireNonEmpty(input, "testParam"));
    }

    @Test
    @DisplayName("requireNonEmpty collection should throw for empty collections")
    public void testRequireNonEmptyCollectionWithEmptyCollection() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty(Collections.emptyList(), "testParam"));

        assertTrue(ex.getMessage().contains("testParam cannot be null or empty"));
    }

    @Test
    @DisplayName("requireNonEmpty collection should throw for null collections")
    public void testRequireNonEmptyCollectionWithNull() {
        List<String> nullList = null;
        assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonEmpty(nullList, "testParam"));
    }

    // =========================================================================
    //  requireNonNull
    // =========================================================================

    @Test
    @DisplayName("requireNonNull should accept non-null objects")
    public void testRequireNonNullWithValidObject() {
        Object input = new Object();
        assertEquals(input, ValidationUtils.requireNonNull(input, "testParam"));
    }

    @Test
    @DisplayName("requireNonNull should throw for null objects")
    public void testRequireNonNullWithNull() {
        Exception ex = assertThrows(IllegalArgumentException.class, () ->
                ValidationUtils.requireNonNull(null, "testParam"));

        assertTrue(ex.getMessage().contains("testParam cannot be null"));
    }

    // =========================================================================
    //  softValidate
    // =========================================================================

    @Test
    @DisplayName("softValidate should return true for valid conditions")
    public void testSoftValidateWithValidCondition() {
        assertTrue(ValidationUtils.softValidate(true, "This should pass"));
    }

    @Test
    @DisplayName("softValidate should return false for invalid conditions")
    public void testSoftValidateWithInvalidCondition() {
        assertFalse(ValidationUtils.softValidate(false, "This should fail"));
    }
}
