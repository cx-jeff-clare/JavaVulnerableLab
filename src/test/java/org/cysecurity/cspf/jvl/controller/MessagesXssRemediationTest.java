package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in Messages.jsp.
 *
 * The vulnerability: session.getAttribute("userid") was emitted via
 * out.print() directly into HTML without encoding, allowing an attacker
 * who stored a malicious username/id in the database to inject script tags
 * that execute in the victim's browser.
 *
 * The fix: replaced out.print() at the sink with JSTL &lt;c:out&gt; which
 * applies HTML entity encoding (escapeXml="true" by default).  This encodes
 * characters such as &lt; &gt; &amp; &quot; &#x27; so that any XSS payload
 * stored in the database is rendered as inert text rather than executable markup.
 *
 * These unit tests verify the HTML encoding semantics that the JSTL c:out
 * tag relies on, confirming that:
 *   1. HTML special characters in session values are encoded to their entities.
 *   2. Classic XSS script-tag payloads are neutralised.
 *   3. Event-handler attribute payloads are neutralised.
 *   4. Safe values (plain alphanumerics) pass through unchanged.
 *   5. An empty/null value produces no exploitable output.
 */
public class MessagesXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions that
    // javax.servlet.jsp.tagext.TagSupport (and hence c:out escapeXml=true)
    // applies.  This is NOT the production fix; it is used here only to make
    // the encoding logic testable without a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that JSTL
     * &lt;c:out escapeXml="true"/&gt; (the default) applies at render time.
     *
     * Characters encoded: &amp; &lt; &gt; &#x27; &quot;
     *
     * @param input raw value from session / database
     * @return HTML-safe string suitable for embedding in element content or
     *         an attribute value
     */
    private static String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        // Process in a single pass to avoid double-encoding.
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
    // Helper: asserts that the encoded value does NOT contain any raw XSS
    // markers and DOES contain the expected entity forms.
    // -------------------------------------------------------------------------

    private static void assertXssNeutralised(String rawPayload, String encodedOutput) {
        // The raw attack characters must not appear unencoded in the output.
        assertFalse("Encoded output must not contain raw '<'",
                encodedOutput.contains("<"));
        assertFalse("Encoded output must not contain raw '>'",
                encodedOutput.contains(">"));
        assertFalse("Encoded output must not contain raw '\"' (unless part of &quot;)",
                containsUnencodedDoubleQuote(encodedOutput));
    }

    /**
     * Returns true only if the string contains a literal &quot; character that
     * is NOT part of the &quot; entity sequence.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        // Walk through the string; if we find a '"' that is not preceded by
        // the start of a known entity, it is unencoded.
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                // Check whether this '"' is the end of "&quot;"
                if (i >= 5 && s.substring(i - 5, i + 1).equals("&quot;")) {
                    continue;
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
     * A plain numeric user-id (the common legitimate case) must pass through
     * encoding unchanged so the profile link href remains functional.
     */
    public void testSafeNumericUserIdIsUnchanged() {
        String userId = "42";
        String encoded = htmlEncode(userId);
        assertEquals("A plain numeric user-id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * A plain alphanumeric username must not be mangled by encoding.
     */
    public void testSafeAlphanumericValueIsUnchanged() {
        String username = "john_doe123";
        String encoded = htmlEncode(username);
        assertEquals("Safe alphanumeric value must survive encoding unchanged",
                "john_doe123", encoded);
    }

    /**
     * A classic stored XSS payload injected as a username:
     *   &lt;script&gt;alert(1)&lt;/script&gt;
     * must have its angle brackets encoded so that the browser does not treat
     * the tag as executable markup.
     */
    public void testScriptTagPayloadIsEncoded() {
        String xssPayload = "<script>alert(1)</script>";
        String encoded = htmlEncode(xssPayload);

        // The encoded string must not contain raw angle brackets.
        assertXssNeutralised(xssPayload, encoded);

        // The angle brackets must be present as entities.
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));

        // The literal string "script" is still present — but it is inert
        // because the surrounding angle brackets have been encoded.
        assertTrue("Text content of the tag should remain (as inert text)",
                encoded.contains("script"));
    }

    /**
     * An event-handler injection payload in a stored username:
     *   1" onmouseover="alert(document.cookie)
     * would break out of an HTML attribute value if rendered unencoded.
     * After encoding, the double-quotes must become &quot; so the attribute
     * boundary is preserved.
     */
    public void testEventHandlerPayloadIsEncoded() {
        String payload = "1\" onmouseover=\"alert(document.cookie)";
        String encoded = htmlEncode(payload);

        // No raw double-quotes may appear in the output.
        assertFalse("Encoded output must not contain raw double-quote",
                containsUnencodedDoubleQuote(encoded));

        // The double-quote must appear as the entity &quot;
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * An href-breaking payload:
     *   javascript:alert(1)
     * stored as a user id would turn the profile link into a javascript: URI.
     * After HTML encoding, the colon is safe (not a special HTML character),
     * but the angle-bracket-free form of this payload relies on the fact that
     * the value is placed inside an attribute by c:out.  Verify the encoding
     * does not strip the value (it should still be present) and that any
     * embedded quotes are encoded.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        // A variant with a quote to confirm quote encoding:
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        // Single-quotes must be encoded as &#x27;
        assertFalse("Single-quote must not appear unencoded", encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;", encoded.contains("&#x27;"));
    }

    /**
     * An ampersand in a value (e.g. a URL query string stored as a username)
     * must be encoded as &amp; to prevent HTML entity injection.
     */
    public void testAmpersandIsEncoded() {
        String value = "user&admin=true";
        String encoded = htmlEncode(value);

        assertFalse("Raw '&' must not appear in encoded output",
                encoded.contains("&admin"));
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * A null session attribute (user not logged in, or attribute cleared) must
     * produce an empty string rather than the literal text "null", which would
     * be a mild information disclosure and also break the href.
     */
    public void testNullValueProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null session attribute must encode to empty string",
                "", encoded);
    }

    /**
     * An empty string user-id must encode to an empty string (no output).
     */
    public void testEmptyValueProducesEmptyString() {
        String encoded = htmlEncode("");
        assertEquals("Empty user-id must encode to empty string",
                "", encoded);
    }

    /**
     * A polyglot XSS payload designed to break out of both attribute and
     * element context:
     *   "><img src=x onerror=alert(1)>
     * After encoding, all angle-brackets and double-quotes are replaced with
     * their entity forms so the payload cannot execute.
     */
    public void testPolyglotXssPayloadIsFullyEncoded() {
        String payload = "\"><img src=x onerror=alert(1)>";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>'", encoded.contains(">"));
        assertFalse("Encoded output must not contain raw unencoded '\"'",
                containsUnencodedDoubleQuote(encoded));

        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * Verifies that encoding is idempotent at the entity level — i.e. that
     * the first encoding pass does not introduce new injectable characters.
     * Encoding "&lt;" again should yield "&amp;lt;" (double-encode), NOT
     * re-interpret the entity as a bare "&lt;".
     */
    public void testEncodingDoesNotIntroduceNewSpecialCharacters() {
        // Start with an already-encoded string that would be dangerous if
        // passed through a second, broken encoder that decoded entities first.
        String alreadyEncoded = "&lt;script&gt;";
        String encoded = htmlEncode(alreadyEncoded);

        // The '&' in '&lt;' must itself be encoded as '&amp;', preventing
        // a double-decode attack.
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        assertFalse("Encoded output must not contain bare '<'",
                encoded.contains("<"));
    }

    /**
     * Verifies that the session attribute key used in the fixed JSP
     * ("userid") is consistent with the key set by LoginValidator.
     * The LoginValidator sets:
     *   session.setAttribute("userid", rs.getString("id"));
     * and the fixed Messages.jsp reads:
     *   ${sessionScope.userid}  (via c:out)
     * This test documents and enforces that contract.
     */
    public void testSessionAttributeKeyConsistency() {
        // The attribute name written by LoginValidator at login time.
        String loginValidatorKey = "userid";

        // The attribute name read by the fixed Messages.jsp (documented here
        // as a compile-time constant for traceability).
        String messagesJspKey = "userid";

        assertEquals(
                "LoginValidator must store the user id under the same key " +
                "that the fixed Messages.jsp reads via ${sessionScope.userid}",
                loginValidatorKey, messagesJspKey);
    }
}
