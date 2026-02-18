package com.securitybridge;

import org.owasp.html.HtmlChangeListener;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * HTML sanitization using the OWASP Java HTML Sanitizer library.
 *
 * <p>Provides three built-in policies of increasing permissiveness:</p>
 * <ul>
 *   <li><strong>STRICT</strong> — strips all HTML, returns plain text only</li>
 *   <li><strong>BASIC</strong> — allows formatting tags ({@code <b>}, {@code <i>},
 *       {@code <em>}, {@code <strong>}, {@code <u>}, {@code <br>}, {@code <p>},
 *       {@code <ul>}, {@code <ol>}, {@code <li>}, {@code <blockquote>})</li>
 *   <li><strong>RICH</strong> — allows BASIC plus links, images, tables, and
 *       headings ({@code <a>}, {@code <img>}, {@code <table>}, {@code <h1>}–{@code <h6>})</li>
 * </ul>
 *
 * <p>Custom policies can be registered via {@link #registerPolicy(String, PolicyFactory)}.</p>
 *
 * <h3>Sanitization Reports</h3>
 * Use {@link #sanitizeWithReport(String, String)} to obtain both the sanitized
 * HTML and a list of elements/attributes that were stripped, useful for
 * auditing and logging.
 *
 * <h3>Thread Safety</h3>
 * All {@link PolicyFactory} instances are immutable and thread-safe.
 * The policy registry uses a {@link ConcurrentHashMap}.
 *
 * <h3>Usage Examples</h3>
 * <pre>{@code
 * HtmlSanitizer sanitizer = new HtmlSanitizer();
 *
 * // Strip all HTML
 * String text = sanitizer.sanitize("<script>alert('xss')</script>Hello", "STRICT");
 * // → "Hello"
 *
 * // Allow basic formatting
 * String html = sanitizer.sanitize("<b>Bold</b><script>bad</script>", "BASIC");
 * // → "<b>Bold</b>"
 *
 * // Sanitize with audit report
 * SanitizationResult result = sanitizer.sanitizeWithReport(input, "RICH");
 * result.getSanitizedHtml();
 * result.getStrippedElements();   // e.g. ["script", "iframe"]
 * result.getStrippedAttributes(); // e.g. ["onclick"]
 * }</pre>
 *
 * @see <a href="https://github.com/OWASP/java-html-sanitizer">OWASP Java HTML Sanitizer</a>
 */
public class HtmlSanitizer {

    private static final Logger LOGGER = Logger.getLogger(HtmlSanitizer.class.getName());

    /** Maximum input length to prevent processing abuse. */
    private static final int MAX_HTML_LENGTH = 100_000;

    /** Policy name constant: strips all HTML. */
    public static final String POLICY_STRICT = "STRICT";

    /** Policy name constant: basic formatting only. */
    public static final String POLICY_BASIC = "BASIC";

    /** Policy name constant: rich content including links, images, tables. */
    public static final String POLICY_RICH = "RICH";

    private final Map<String, PolicyFactory> policies;

    // =========================================================================
    //  Construction
    // =========================================================================

    /**
     * Creates a sanitizer with the three built-in policies (STRICT, BASIC, RICH).
     */
    public HtmlSanitizer() {
        this.policies = new ConcurrentHashMap<>();
        policies.put(POLICY_STRICT, buildStrictPolicy());
        policies.put(POLICY_BASIC, buildBasicPolicy());
        policies.put(POLICY_RICH, buildRichPolicy());
    }

    // =========================================================================
    //  Public API — Sanitize
    // =========================================================================

    /**
     * Sanitizes HTML input using the named policy.
     *
     * @param html       the untrusted HTML string
     * @param policyName one of {@code STRICT}, {@code BASIC}, {@code RICH},
     *                   or a custom-registered policy name
     * @return the sanitized HTML string
     * @throws IllegalArgumentException if input is null/empty, too long,
     *         or the policy name is not registered
     */
    public String sanitize(String html, String policyName) {
        ValidationUtils.requireNonEmpty(html, "html");
        enforceMaxHtmlLength(html);
        PolicyFactory policy = resolvePolicy(policyName);

        String result = policy.sanitize(html);
        LOGGER.fine("Sanitized HTML with policy '" + policyName
                + "' (input=" + html.length() + " chars, output=" + result.length() + " chars)");
        return result;
    }

    /**
     * Sanitizes HTML input and returns a detailed report of what was stripped.
     *
     * @param html       the untrusted HTML string
     * @param policyName the policy to apply
     * @return a {@link SanitizationResult} with sanitized output and audit data
     * @throws IllegalArgumentException if input is null/empty, too long,
     *         or the policy name is not registered
     */
    public SanitizationResult sanitizeWithReport(String html, String policyName) {
        ValidationUtils.requireNonEmpty(html, "html");
        enforceMaxHtmlLength(html);
        PolicyFactory policy = resolvePolicy(policyName);

        List<String> strippedElements = new ArrayList<>();
        List<String> strippedAttributes = new ArrayList<>();

        HtmlChangeListener<Void> listener = new HtmlChangeListener<>() {
            @Override
            public void discardedTag(Void context, String elementName) {
                strippedElements.add(elementName);
            }

            @Override
            public void discardedAttributes(Void context, String elementName,
                                            String... attributeNames) {
                for (String attr : attributeNames) {
                    strippedAttributes.add(elementName + "." + attr);
                }
            }
        };

        String sanitized = policy.sanitize(html, listener, null);

        if (!strippedElements.isEmpty() || !strippedAttributes.isEmpty()) {
            LOGGER.info("Sanitization stripped " + strippedElements.size()
                    + " elements and " + strippedAttributes.size()
                    + " attributes using policy '" + policyName + "'");
        }

        return new SanitizationResult(sanitized, strippedElements, strippedAttributes);
    }

    // =========================================================================
    //  Policy Management
    // =========================================================================

    /**
     * Registers a custom policy under the given name.
     *
     * <p>Overwrites any existing policy with the same name, including
     * built-in policies.</p>
     *
     * @param name   non-empty policy name
     * @param policy non-null policy factory
     */
    public void registerPolicy(String name, PolicyFactory policy) {
        ValidationUtils.requireNonEmpty(name, "name");
        ValidationUtils.requireNonNull(policy, "policy");
        policies.put(name, policy);
        LOGGER.info("Registered custom sanitization policy: " + name);
    }

    /**
     * Returns the names of all registered policies.
     *
     * @return unmodifiable set of policy names
     */
    public java.util.Set<String> getPolicyNames() {
        return Collections.unmodifiableSet(policies.keySet());
    }

    // =========================================================================
    //  Built-in Policy Definitions
    // =========================================================================

    /**
     * STRICT: strips all HTML tags, returning plain text only.
     */
    private static PolicyFactory buildStrictPolicy() {
        return new HtmlPolicyBuilder().toFactory();
    }

    /**
     * BASIC: allows common formatting elements.
     */
    private static PolicyFactory buildBasicPolicy() {
        return Sanitizers.FORMATTING
                .and(Sanitizers.BLOCKS)
                .and(new HtmlPolicyBuilder()
                        .allowElements("br", "p", "ul", "ol", "li", "blockquote")
                        .toFactory());
    }

    /**
     * RICH: allows formatting, links, images, tables, and headings.
     */
    private static PolicyFactory buildRichPolicy() {
        return buildBasicPolicy()
                .and(Sanitizers.LINKS)
                .and(Sanitizers.IMAGES)
                .and(Sanitizers.TABLES)
                .and(new HtmlPolicyBuilder()
                        .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
                        .toFactory());
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    /**
     * Resolves a policy name to a {@link PolicyFactory}.
     */
    private PolicyFactory resolvePolicy(String policyName) {
        ValidationUtils.requireNonEmpty(policyName, "policyName");
        PolicyFactory policy = policies.get(policyName.toUpperCase());
        if (policy == null) {
            throw new IllegalArgumentException(
                    "Unknown sanitization policy: '" + policyName
                    + "'. Available: " + policies.keySet());
        }
        return policy;
    }

    /**
     * Enforces maximum HTML input length.
     */
    private static void enforceMaxHtmlLength(String html) {
        if (html.length() > MAX_HTML_LENGTH) {
            throw new IllegalArgumentException(
                    "HTML input exceeds maximum length of " + MAX_HTML_LENGTH
                    + " characters (got " + html.length() + ")");
        }
    }

    // =========================================================================
    //  Result Class
    // =========================================================================

    /**
     * Result of a sanitization with audit report.
     *
     * <p>Immutable — all lists are unmodifiable copies.</p>
     */
    public static class SanitizationResult {

        private final String sanitizedHtml;
        private final List<String> strippedElements;
        private final List<String> strippedAttributes;

        public SanitizationResult(String sanitizedHtml,
                                  List<String> strippedElements,
                                  List<String> strippedAttributes) {
            this.sanitizedHtml = sanitizedHtml;
            this.strippedElements = List.copyOf(strippedElements);
            this.strippedAttributes = List.copyOf(strippedAttributes);
        }

        /** Returns the sanitized HTML string. */
        public String getSanitizedHtml() {
            return sanitizedHtml;
        }

        /** Returns the list of HTML elements that were stripped. */
        public List<String> getStrippedElements() {
            return strippedElements;
        }

        /** Returns the list of attributes stripped (format: element.attribute). */
        public List<String> getStrippedAttributes() {
            return strippedAttributes;
        }

        /** Returns {@code true} if any content was modified. */
        public boolean wasModified() {
            return !strippedElements.isEmpty() || !strippedAttributes.isEmpty();
        }
    }
}
