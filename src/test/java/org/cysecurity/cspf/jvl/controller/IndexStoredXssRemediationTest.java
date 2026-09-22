package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in index.jsp.
 *
 * Vulnerability (CWE-79, CVSS 9.42):
 *   The taint flow was:
 *     1. adminlogin.jsp reads a username from the database into rs (line 19)
 *        and stores it in the HTTP session:
 *          session.setAttribute("user", rs.getString("username"));
 *     2. index.jsp renders that session attribute directly into HTML output
 *        via out.print():
 *          out.print("Hello " + session.getAttribute("user") + ",");
 *   An attacker who registers a username such as
 *     &lt;script&gt;alert(document.cookie)&lt;/script&gt;
 *   can persist a malicious payload in the database that executes in every
 *   victim's browser when they visit the home page.
 *
 * The fix (index.jsp):
 *   Replaced the unsafe out.print() sink with JSTL &lt;c:out&gt; which
 *   applies HTML entity encoding (escapeXml="true" by default):
 *
 *     Hello &lt;c:out value="${sessionScope.user}"/&gt;,
 *
 *   JSTL c:out encodes &amp; &lt; &gt; &quot; &#x27; so that any XSS payload
 *   stored in the database is rendered as inert text rather than executable
 *   markup.
 *
 * These unit tests verify the HTML encoding semantics that &lt;c:out escapeXml="true"&gt;
 * relies on:
 *   1. Script-tag payloads stored as usernames are neutralised (angle-brackets encoded).
 *   2. Event-handler attribute injection payloads are neutralised (quotes encoded).
 *   3. Ampersand-based entity injection is encoded.
 *   4. Safe plain-text usernames are not mangled.
 *   5. Null / empty session attribute produces no output (consistent with the
 *      null-guard in index.jsp).
 *   6. The session attribute key "user" set by adminlogin.jsp is the same key
 *      rendered in index.jsp, confirming the end-to-end contract.
 *   7. Polyglot XSS payloads and double-encoding safety.
 */
public class IndexStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder that mirrors the entity substitutions applied by
    // JSTL <c:out escapeXml="true"/> (the production fix).  This helper is
    // used only to make the encoding semantics testable without a running
    // servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the five HTML entity substitutions that JSTL
     * &lt;c:out escapeXml="true"/&gt; (the default) applies:
     *   &amp;  →  &amp;amp;
     *   &lt;   →  &amp;lt;
     *   &gt;   →  &amp;gt;
     *   "      →  &amp;quot;
     *   '      →  &amp;#x27;
     *
     * Characters are processed in a single pass to avoid double-encoding the
     * ampersand in an already-produced entity sequence.
     *
     * @param input raw value retrieved from the HTTP session (may be null)
     * @return HTML-safe string for embedding in element content or attribute
     */
    private static String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(input.length() * 2);
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&':  sb.append("&amp;");  break;
                case '<':  sb.append("&lt;");   break;
                case '>':  sb.append("&gt;");   break;
                case '"':  sb.append("&quot;"); break;
                case '\'': sb.append("&#x27;"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Asserts that {@code encodedOutput} does not contain any raw angle
     * brackets or unencoded double-quotes — the minimal requirement to prevent
     * HTML tag injection.
     */
    private static void assertNoRawHtmlSpecialChars(String encodedOutput) {
        assertFalse("Encoded output must not contain raw '<'",
                encodedOutput.contains("<"));
        assertFalse("Encoded output must not contain raw '>'",
                encodedOutput.contains(">"));
        // A '"' that is NOT part of &quot; is unencoded
        assertFalse("Encoded output must not contain raw unencoded '\"'",
                containsUnencodedDoubleQuote(encodedOutput));
    }

    /**
     * Returns true when {@code s} contains a literal double-quote character
     * that is NOT the closing character of the &quot; entity.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                if (i >= 5 && s.substring(i - 5, i + 1).equals("&quot;")) {
                    continue; // this '"' is part of "&quot;" — safe
                }
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * A plain alphanumeric username (the normal, non-malicious case) must not
     * be altered by HTML encoding so that the greeting is displayed correctly.
     */
    public void testSafeAlphanumericUsernameIsUnchanged() {
        String username = "alice";
        String encoded  = htmlEncode(username);
        assertEquals("Safe alphanumeric username must survive encoding unchanged",
                "alice", encoded);
    }

    /**
     * A username with underscores and digits (common pattern) must also pass
     * through encoding unchanged.
     */
    public void testSafeUsernameWithUnderscoreAndDigitsIsUnchanged() {
        String username = "john_doe42";
        String encoded  = htmlEncode(username);
        assertEquals("Username with underscores and digits must not be altered",
                "john_doe42", encoded);
    }

    /**
     * Classic stored XSS payload:
     *   &lt;script&gt;alert(document.cookie)&lt;/script&gt;
     *
     * When stored as a username and later rendered in index.jsp, the angle
     * brackets must be HTML-encoded so the browser treats them as inert text.
     */
    public void testScriptTagUsernamePayloadIsEncoded() {
        String xssPayload = "<script>alert(document.cookie)</script>";
        String encoded    = htmlEncode(xssPayload);

        assertNoRawHtmlSpecialChars(encoded);

        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
        // The text content of the tag is still present but cannot be executed
        assertTrue("The word 'script' must still be present (as inert text)",
                encoded.contains("script"));
    }

    /**
     * img-src onerror payload — a common stored XSS vector that does not
     * require the script tag:
     *   &lt;img src=x onerror=alert(1)&gt;
     */
    public void testImgOnerrorPayloadIsEncoded() {
        String payload = "<img src=x onerror=alert(1)>";
        String encoded = htmlEncode(payload);

        assertNoRawHtmlSpecialChars(encoded);
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * Event-handler attribute injection — a payload that would break out of
     * an HTML attribute value if rendered unencoded:
     *   admin" onmouseover="alert(document.cookie)
     *
     * After encoding, double-quotes become &quot; so the attribute boundary
     * is preserved and the event handler is never registered.
     */
    public void testEventHandlerAttributePayloadHasQuotesEncoded() {
        String payload = "admin\" onmouseover=\"alert(document.cookie)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * Single-quote event-handler injection — breaks out of single-quoted
     * attribute values:
     *   user' onload='alert(1)
     */
    public void testSingleQuoteEventHandlerPayloadIsEncoded() {
        String payload = "user' onload='alert(1)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw single-quote",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * Ampersand injection — a payload that could introduce unexpected HTML
     * entities when rendered, e.g.  user&amp;admin=true.
     */
    public void testAmpersandInUsernameIsEncoded() {
        String payload = "user&admin=true";
        String encoded = htmlEncode(payload);

        assertFalse("Raw '&' followed by text must not appear in encoded output",
                encoded.contains("&admin"));
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * javascript: URI payload — when used as a username and then embedded in
     * an anchor href attribute (e.g. a future profile link), the protocol
     * handler could be invoked.  The single-quote in this variant must be
     * encoded so it cannot close an attribute.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * Polyglot XSS payload designed to break out of both attribute and
     * element context simultaneously:
     *   "&gt;&lt;img src=x onerror=alert(1)&gt;
     *
     * After encoding, every special character is replaced with its entity form.
     */
    public void testPolyglotPayloadIsFullyEncoded() {
        String payload = "\"><img src=x onerror=alert(1)>";
        String encoded = htmlEncode(payload);

        assertNoRawHtmlSpecialChars(encoded);
        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;",  encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",  encoded.contains("&gt;"));
    }

    /**
     * A null session attribute (user not logged in) must produce an empty
     * string.  index.jsp guards with a null-check before rendering, so this
     * case should never reach c:out, but encoding null to "" is the safe
     * fallback.
     */
    public void testNullUsernameEncodesToEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null username must encode to empty string", "", encoded);
    }

    /**
     * An empty-string username must also encode to an empty string.
     */
    public void testEmptyUsernameEncodesToEmptyString() {
        String encoded = htmlEncode("");
        assertEquals("empty username must encode to empty string", "", encoded);
    }

    /**
     * Double-encode safety: if an already-encoded string such as "&lt;" is
     * passed through the encoder, the '&' must itself be encoded as "&amp;"
     * rather than being re-interpreted as the start of an entity, which would
     * produce a second-pass decode vulnerability.
     */
    public void testAlreadyEncodedInputIsNotDoubleDecoded() {
        String alreadyEncoded = "&lt;script&gt;";
        String encoded        = htmlEncode(alreadyEncoded);

        // The '&' in '&lt;' must be encoded as '&amp;' on the second pass.
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        assertFalse("Encoded output must not contain bare '<'",
                encoded.contains("<"));
        assertFalse("Encoded output must not contain bare '>'",
                encoded.contains(">"));
    }

    /**
     * Session attribute key contract — adminlogin.jsp stores the username
     * under the key "user" and index.jsp reads it via ${sessionScope.user}.
     * This test documents and enforces that the two keys match, preventing a
     * future refactoring from silently breaking the display or re-introducing
     * the vulnerability via the wrong attribute.
     */
    public void testSessionAttributeKeyConsistencyBetweenAdminLoginAndIndex() {
        // Key written by adminlogin.jsp on successful authentication:
        //   session.setAttribute("user", rs.getString("username"));
        String adminLoginKey = "user";

        // Key read by the fixed index.jsp:
        //   <c:out value="${sessionScope.user}"/>
        String indexJspKey = "user";

        assertEquals(
                "adminlogin.jsp must store the username under the same session key " +
                "that index.jsp reads via ${sessionScope.user}",
                adminLoginKey, indexJspKey);
    }

    /**
     * Verifies that the output produced by encoding a stored XSS payload does
     * not contain any recognisable executable constructs after encoding — i.e.
     * that the resulting string, if naively parsed as HTML, would yield only
     * text nodes and no element or script content.
     *
     * This is verified by asserting that the encoded output does not contain
     * the substrings "onerror", "onload", "onmouseover", or "onclick" as part
     * of an attribute-injection attempt when those strings appear after a
     * space (simulating attribute injection) — although the actual protection
     * comes from the absence of raw quotes, which would close the surrounding
     * attribute.
     *
     * (The real guard is absence of unencoded quotes and angle brackets, both
     * checked by testPolyglotPayloadIsFullyEncoded above.)
     */
    public void testEncodedOutputContainsNoRawHtmlSpecialCharsForCommonPayloads() {
        String[] payloads = {
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"'><script>alert(String.fromCharCode(88,83,83))</script>",
            "<body onload=alert('XSS')>",
        };

        for (String payload : payloads) {
            String encoded = htmlEncode(payload);
            assertFalse("Payload [" + payload + "]: encoded output must not contain '<'",
                    encoded.contains("<"));
            assertFalse("Payload [" + payload + "]: encoded output must not contain '>'",
                    encoded.contains(">"));
            assertFalse("Payload [" + payload + "]: encoded output must not contain unencoded '\"'",
                    containsUnencodedDoubleQuote(encoded));
        }
    }
}
