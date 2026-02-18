package com.securitybridge;

import com.securitybridge.HtmlSanitizer.SanitizationResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("HtmlSanitizer")
class HtmlSanitizerTest {

    private HtmlSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        sanitizer = new HtmlSanitizer();
    }

    // =========================================================================
    //  STRICT Policy
    // =========================================================================

    @Nested
    @DisplayName("STRICT policy — text only")
    class StrictTests {

        @Test
        @DisplayName("strips all HTML tags")
        void stripsAllTags() {
            assertEquals("Hello World", sanitizer.sanitize("<b>Hello</b> <i>World</i>", "STRICT"));
        }

        @Test
        @DisplayName("strips script tags and content")
        void stripsScript() {
            String result = sanitizer.sanitize("<script>alert('xss')</script>Safe", "STRICT");
            assertFalse(result.contains("script"));
            assertTrue(result.contains("Safe"));
        }

        @Test
        @DisplayName("strips iframe tags")
        void stripsIframe() {
            String result = sanitizer.sanitize("<iframe src='evil.com'></iframe>Text", "STRICT");
            assertFalse(result.contains("iframe"));
            assertTrue(result.contains("Text"));
        }

        @Test
        @DisplayName("strips event handlers")
        void stripsEventHandlers() {
            String result = sanitizer.sanitize("<div onclick='steal()'>Click</div>", "STRICT");
            assertFalse(result.contains("onclick"));
            assertTrue(result.contains("Click"));
        }

        @Test
        @DisplayName("plain text passes through unchanged")
        void plainTextUnchanged() {
            assertEquals("Hello World", sanitizer.sanitize("Hello World", "STRICT"));
        }

        @Test
        @DisplayName("HTML entities preserved")
        void entitiesPreserved() {
            String result = sanitizer.sanitize("5 &gt; 3 &amp; 2 &lt; 4", "STRICT");
            assertTrue(result.contains("&gt;") || result.contains(">"));
        }
    }

    // =========================================================================
    //  BASIC Policy
    // =========================================================================

    @Nested
    @DisplayName("BASIC policy — formatting tags")
    class BasicTests {

        @Test
        @DisplayName("allows bold and italic")
        void allowsBoldItalic() {
            String result = sanitizer.sanitize("<b>Bold</b> and <i>Italic</i>", "BASIC");
            assertTrue(result.contains("<b>Bold</b>"));
            assertTrue(result.contains("<i>Italic</i>"));
        }

        @Test
        @DisplayName("allows paragraph tags")
        void allowsParagraph() {
            String result = sanitizer.sanitize("<p>Paragraph</p>", "BASIC");
            assertTrue(result.contains("<p>"));
        }

        @Test
        @DisplayName("allows list elements")
        void allowsLists() {
            String input = "<ul><li>Item 1</li><li>Item 2</li></ul>";
            String result = sanitizer.sanitize(input, "BASIC");
            assertTrue(result.contains("<ul>"));
            assertTrue(result.contains("<li>"));
        }

        @Test
        @DisplayName("allows blockquote")
        void allowsBlockquote() {
            String result = sanitizer.sanitize("<blockquote>Quote</blockquote>", "BASIC");
            assertTrue(result.contains("<blockquote>"));
        }

        @Test
        @DisplayName("still strips script tags")
        void stillStripsScript() {
            String result = sanitizer.sanitize("<b>OK</b><script>bad()</script>", "BASIC");
            assertTrue(result.contains("<b>OK</b>"));
            assertFalse(result.contains("script"));
        }

        @Test
        @DisplayName("strips link tags")
        void stripsLinks() {
            String result = sanitizer.sanitize("<a href='http://evil.com'>Click</a>", "BASIC");
            assertFalse(result.contains("<a "));
        }

        @Test
        @DisplayName("strips image tags")
        void stripsImages() {
            String result = sanitizer.sanitize("<img src='tracker.gif'/>", "BASIC");
            assertFalse(result.contains("<img"));
        }
    }

    // =========================================================================
    //  RICH Policy
    // =========================================================================

    @Nested
    @DisplayName("RICH policy — links, images, tables, headings")
    class RichTests {

        @Test
        @DisplayName("allows links with href")
        void allowsLinks() {
            String result = sanitizer.sanitize(
                    "<a href='https://example.com'>Link</a>", "RICH");
            assertTrue(result.contains("<a "));
            assertTrue(result.contains("href"));
        }

        @Test
        @DisplayName("allows images with src and alt")
        void allowsImages() {
            String result = sanitizer.sanitize(
                    "<img src='https://example.com/img.png' alt='photo' />", "RICH");
            assertTrue(result.contains("<img "));
        }

        @Test
        @DisplayName("allows table elements")
        void allowsTables() {
            String input = "<table><tr><td>Cell</td></tr></table>";
            String result = sanitizer.sanitize(input, "RICH");
            assertTrue(result.contains("<table>"));
            assertTrue(result.contains("<td>"));
        }

        @Test
        @DisplayName("allows heading tags h1-h6")
        void allowsHeadings() {
            String result = sanitizer.sanitize("<h1>Title</h1><h3>Sub</h3>", "RICH");
            assertTrue(result.contains("<h1>"));
            assertTrue(result.contains("<h3>"));
        }

        @Test
        @DisplayName("still strips script and iframe")
        void stillStripsXss() {
            String input = "<h1>Title</h1><script>xss()</script><iframe></iframe>";
            String result = sanitizer.sanitize(input, "RICH");
            assertTrue(result.contains("<h1>"));
            assertFalse(result.contains("script"));
            assertFalse(result.contains("iframe"));
        }

        @Test
        @DisplayName("strips javascript: protocol in links")
        void stripsJavascriptProtocol() {
            String result = sanitizer.sanitize(
                    "<a href='javascript:alert(1)'>Click</a>", "RICH");
            assertFalse(result.contains("javascript"));
        }
    }

    // =========================================================================
    //  XSS Attack Vectors
    // =========================================================================

    @Nested
    @DisplayName("XSS attack vectors")
    class XssTests {

        @Test
        @DisplayName("script injection in img onerror")
        void imgOnerror() {
            String input = "<img src=x onerror='alert(1)' />";
            String result = sanitizer.sanitize(input, "RICH");
            assertFalse(result.contains("onerror"));
        }

        @Test
        @DisplayName("SVG-based XSS")
        void svgXss() {
            String input = "<svg onload='alert(1)'>test</svg>";
            String result = sanitizer.sanitize(input, "RICH");
            assertFalse(result.contains("svg"));
            assertFalse(result.contains("onload"));
        }

        @Test
        @DisplayName("style-based XSS")
        void styleXss() {
            String input = "<div style='background:url(javascript:alert(1))'>text</div>";
            String result = sanitizer.sanitize(input, "STRICT");
            assertFalse(result.contains("javascript"));
        }

        @Test
        @DisplayName("data URI in image src")
        void dataUri() {
            String input = "<img src='data:text/html,<script>alert(1)</script>' />";
            String result = sanitizer.sanitize(input, "RICH");
            assertFalse(result.contains("data:text/html"));
        }

        @Test
        @DisplayName("nested tag evasion")
        void nestedEvasion() {
            String input = "<<script>alert(1)</script>";
            String result = sanitizer.sanitize(input, "STRICT");
            assertFalse(result.contains("script"));
        }
    }

    // =========================================================================
    //  Sanitize With Report
    // =========================================================================

    @Nested
    @DisplayName("Sanitization reports")
    class ReportTests {

        @Test
        @DisplayName("report captures stripped elements")
        void capturesStrippedElements() {
            SanitizationResult result = sanitizer.sanitizeWithReport(
                    "<script>bad</script><b>OK</b>", "BASIC");
            assertTrue(result.getStrippedElements().contains("script"));
            assertTrue(result.getSanitizedHtml().contains("<b>OK</b>"));
            assertTrue(result.wasModified());
        }

        @Test
        @DisplayName("report captures stripped attributes")
        void capturesStrippedAttributes() {
            SanitizationResult result = sanitizer.sanitizeWithReport(
                    "<div onclick='hack()'>Text</div>", "RICH");
            assertTrue(result.wasModified());
        }

        @Test
        @DisplayName("clean input produces empty report")
        void cleanInput() {
            SanitizationResult result = sanitizer.sanitizeWithReport("Just text", "STRICT");
            assertTrue(result.getStrippedElements().isEmpty());
            assertTrue(result.getStrippedAttributes().isEmpty());
            assertFalse(result.wasModified());
        }

        @Test
        @DisplayName("result lists are immutable")
        void immutableLists() {
            SanitizationResult result = sanitizer.sanitizeWithReport("<b>OK</b>", "STRICT");
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getStrippedElements().add("fake"));
            assertThrows(UnsupportedOperationException.class,
                    () -> result.getStrippedAttributes().add("fake"));
        }
    }

    // =========================================================================
    //  Custom Policies
    // =========================================================================

    @Nested
    @DisplayName("Custom policies")
    class CustomPolicyTests {

        @Test
        @DisplayName("register and use custom policy")
        void registerCustom() {
            PolicyFactory codePolicy = new HtmlPolicyBuilder()
                    .allowElements("code", "pre")
                    .toFactory();
            sanitizer.registerPolicy("CODE", codePolicy);

            String result = sanitizer.sanitize("<code>x = 1</code><b>no</b>", "CODE");
            assertTrue(result.contains("<code>"));
            assertFalse(result.contains("<b>"));
        }

        @Test
        @DisplayName("policy names are case-insensitive")
        void caseInsensitive() {
            String result1 = sanitizer.sanitize("<b>text</b>", "strict");
            String result2 = sanitizer.sanitize("<b>text</b>", "STRICT");
            assertEquals(result1, result2);
        }

        @Test
        @DisplayName("unknown policy throws")
        void unknownPolicy() {
            assertThrows(IllegalArgumentException.class,
                    () -> sanitizer.sanitize("text", "NONEXISTENT"));
        }

        @Test
        @DisplayName("getPolicyNames returns all registered")
        void policyNames() {
            assertTrue(sanitizer.getPolicyNames().contains("STRICT"));
            assertTrue(sanitizer.getPolicyNames().contains("BASIC"));
            assertTrue(sanitizer.getPolicyNames().contains("RICH"));
        }
    }

    // =========================================================================
    //  Input Validation
    // =========================================================================

    @Nested
    @DisplayName("Input validation")
    class InputValidation {

        @Test
        @DisplayName("null input rejected")
        void nullInput() {
            assertThrows(IllegalArgumentException.class,
                    () -> sanitizer.sanitize(null, "STRICT"));
        }

        @Test
        @DisplayName("empty input rejected")
        void emptyInput() {
            assertThrows(IllegalArgumentException.class,
                    () -> sanitizer.sanitize("", "STRICT"));
        }

        @Test
        @DisplayName("null policy rejected")
        void nullPolicy() {
            assertThrows(IllegalArgumentException.class,
                    () -> sanitizer.sanitize("text", null));
        }

        @Test
        @DisplayName("oversized input rejected")
        void oversizedInput() {
            String huge = "x".repeat(100_001);
            assertThrows(IllegalArgumentException.class,
                    () -> sanitizer.sanitize(huge, "STRICT"));
        }
    }
}
