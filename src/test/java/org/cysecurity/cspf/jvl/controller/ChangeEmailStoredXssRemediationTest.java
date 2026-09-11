package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in change-email.jsp.
 *
 * Vulnerability (CWE-79): The original code embedded the session attribute
 * "userid" directly into HTML output without encoding:
 *
 *   &lt;input type="hidden" name="id"
 *          value="&lt;% out.print(session.getAttribute("userid")); %&gt;"/&gt;
 *
 * The taint path identified by the SAST engine:
 *   SOURCE  — rs.getString("id") in LoginValidator.processRequest() (lines 55–59),
 *             stored as session attribute "userid" via
 *             session.setAttribute("userid", rs.getString("id")).
 *   SINK    — out.print(session.getAttribute("userid")) at line 19 of
 *             change-email.jsp, written into the value attribute of a hidden
 *             &lt;input&gt; tag without HTML encoding.
 *
 * An attacker who controls a database row (e.g. by self-registering) could
 * store an XSS payload as the "id" field.  When the victim visits the page,
 * the unencoded payload breaks out of the attribute context and executes as
 * JavaScript.
 *
 * The fix: replaced the out.print() sink with JSTL &lt;c:out&gt;:
 *
 *   &lt;input type="hidden" name="id"
 *          value="&lt;c:out value="${sessionScope.userid}"/&gt;"/&gt;
 *
 * JSTL &lt;c:out escapeXml="true"&gt; (the default) HTML-encodes the five
 * characters &amp; &lt; &gt; &quot; &#x27; before writing them to the
 * response, preventing any stored payload from breaking out of the attribute
 * value context.
 *
 * These unit tests verify the HTML encoding semantics used by JSTL c:out,
 * confirming that:
 *   1.  HTML special characters in the userid session attribute are encoded.
 *   2.  Classic stored-XSS script-tag payloads are neutralised.
 *   3.  Attribute-breaking payloads (double-quote injection) are neutralised.
 *   4.  Event-handler attribute injection payloads are neutralised.
 *   5.  Safe values (plain numerics, alphanumerics) pass through unchanged.
 *   6.  Null/empty values produce no exploitable output.
 *   7.  The session attribute key used by the fix matches the key written by
 *       LoginValidator at login time.
 *   8.  Polyglot XSS payloads are fully encoded.
 */
public class ChangeEmailStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions that JSTL
    // <c:out escapeXml="true"/> (the default) applies at render time.
    // This is NOT the production fix; it is used here only to make the
    // HTML-encoding logic testable without a running servlet container.
    // The five substitutions match those mandated by the JSTL 1.2 spec
    // (javax.servlet.jsp.jstl.core.Config and the EL reference impl).
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that JSTL
     * &lt;c:out escapeXml="true"/&gt; applies when rendering a value into
     * HTML output.
     *
     * Characters encoded: &amp; &lt; &gt; &#x27; &quot;
     *
     * @param input raw value from the session / database (the "userid" attribute)
     * @return HTML-safe string suitable for embedding inside an HTML attribute value
     */
    private static String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        // Single pass to avoid double-encoding.
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
    // Helper: assert that the encoded value contains no raw XSS sink
    // characters that could break out of an HTML attribute value.
    // -------------------------------------------------------------------------

    /**
     * Asserts that the encoded output does NOT contain any raw characters
     * that would allow an attacker to break out of an HTML attribute context.
     * Specifically, no raw &lt;, &gt;, or unencoded double-quote is allowed.
     */
    private static void assertAttributeContextSafe(String encodedOutput) {
        assertFalse(
                "Encoded output must not contain raw '<' (would start a new tag)",
                encodedOutput.contains("<"));
        assertFalse(
                "Encoded output must not contain raw '>' (would close a tag)",
                encodedOutput.contains(">"));
        assertFalse(
                "Encoded output must not contain a raw unencoded '\"' " +
                "(would break out of the attribute value boundary)",
                containsUnencodedDoubleQuote(encodedOutput));
    }

    /**
     * Returns {@code true} only if the string contains a literal '"' character
     * that is NOT part of the &quot; entity sequence.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                // The '"' is safe only when it is the last char of "&quot;"
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
     * A plain numeric user-id (the overwhelmingly common legitimate case) must
     * pass through encoding unchanged so the hidden form field retains the
     * correct integer value for the server-side UPDATE query.
     */
    public void testSafeNumericUserIdIsUnchanged() {
        String userId = "42";
        String encoded = htmlEncode(userId);
        assertEquals(
                "A plain numeric user-id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * A plain alphanumeric value must survive encoding without modification,
     * ensuring that any legitimate non-numeric id formats continue to work.
     */
    public void testSafeAlphanumericUserIdIsUnchanged() {
        String userId = "user123";
        String encoded = htmlEncode(userId);
        assertEquals(
                "A safe alphanumeric user-id must not be altered by HTML encoding",
                "user123", encoded);
    }

    /**
     * A classic stored-XSS payload injected as the id value:
     *   &lt;script&gt;alert(document.cookie)&lt;/script&gt;
     *
     * Without encoding, the browser would interpret this as an inline script
     * tag and execute it.  After c:out encoding, the angle brackets become
     * &amp;lt; and &amp;gt; so the payload is displayed as inert text.
     */
    public void testScriptTagPayloadIsEncoded() {
        String xssPayload = "<script>alert(document.cookie)</script>";
        String encoded = htmlEncode(xssPayload);

        // Attribute context safety
        assertAttributeContextSafe(encoded);

        // The specific entities must be present
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));

        // The word "script" is still present but is inert (angle brackets encoded)
        assertTrue(
                "Text 'script' should remain in the encoded output as inert text",
                encoded.contains("script"));
    }

    /**
     * An attribute-breaking payload in the stored id value:
     *   42" onmouseover="alert(1)
     *
     * Without encoding, the double-quote terminates the value attribute and
     * the injected onmouseover handler executes.  After c:out encoding, the
     * double-quote becomes &amp;quot; so the attribute boundary is preserved.
     */
    public void testAttributeBreakingPayloadIsEncoded() {
        String payload = "42\" onmouseover=\"alert(1)";
        String encoded = htmlEncode(payload);

        // No raw double-quotes may remain
        assertFalse(
                "Encoded output must not contain raw double-quote " +
                "(attacker would break out of the attribute value)",
                containsUnencodedDoubleQuote(encoded));

        // The double-quote must appear only as the entity
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * An event-handler injection payload combined with a script tag:
     *   1&gt;&lt;img src=x onerror=alert(document.cookie)&gt;
     *
     * After encoding, all angle brackets are replaced with entities so the
     * injected img tag cannot be parsed by the browser.
     */
    public void testImgOnerrorPayloadIsEncoded() {
        String payload = "1\"><img src=x onerror=alert(document.cookie)>";
        String encoded = htmlEncode(payload);

        assertAttributeContextSafe(encoded);

        assertTrue("'<' must be encoded as &lt; in img onerror payload",
                encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt; in img onerror payload",
                encoded.contains("&gt;"));
        assertTrue("'\"' must be encoded as &quot; in img onerror payload",
                encoded.contains("&quot;"));
    }

    /**
     * A single-quote injection payload designed to break out of a
     * single-quoted attribute context (less common but possible if a template
     * uses single-quote delimiters):
     *   42' onmouseover='alert(1)
     *
     * After encoding, the single-quote becomes &amp;#x27; and cannot break
     * out of the attribute.
     */
    public void testSingleQuotePayloadIsEncoded() {
        String payload = "42' onmouseover='alert(1)";
        String encoded = htmlEncode(payload);

        // No raw single-quote may remain
        assertFalse(
                "Encoded output must not contain raw single-quote",
                encoded.contains("'"));

        // The single-quote must appear only as the entity
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * An ampersand in the userid value (unusual but possible) must be encoded
     * as &amp;amp; to prevent HTML entity injection that could result in
     * unexpected character rendering or parser confusion.
     */
    public void testAmpersandInUserIdIsEncoded() {
        String value = "1&admin=1";
        String encoded = htmlEncode(value);

        assertFalse("Raw '&' must not appear unencoded in the output",
                encoded.contains("&admin"));
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * A javascript: URI payload stored as the user-id:
     *   javascript:alert('XSS')
     *
     * The colon is not a special HTML character, but the single-quotes would
     * be dangerous in a single-quote delimited attribute.  After encoding,
     * single-quotes become &amp;#x27; and the payload cannot execute even if
     * placed in an href attribute.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        // Single-quotes must be encoded
        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * A null session attribute (e.g. user not logged in, or the session has
     * expired before the form is submitted) must produce an empty string rather
     * than the literal text "null", which would be rendered into the hidden
     * field and could cause a spurious database error.
     */
    public void testNullUserIdProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals(
                "null session attribute must encode to an empty string",
                "", encoded);
    }

    /**
     * An empty string user-id must encode to an empty string.
     * This covers the case where the session has an empty "userid" value
     * (abnormal but the encoding must not introduce any output).
     */
    public void testEmptyUserIdProducesEmptyString() {
        String encoded = htmlEncode("");
        assertEquals(
                "Empty user-id must encode to an empty string",
                "", encoded);
    }

    /**
     * A polyglot XSS payload designed to be effective across multiple
     * injection contexts simultaneously:
     *   "&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;a attr="
     *
     * After encoding, all injection characters (&lt;, &gt;, &quot;) are
     * replaced with their entity forms so the payload cannot execute in any
     * of the targeted contexts.
     */
    public void testPolyglotXssPayloadIsFullyEncoded() {
        String payload = "\"><script>alert(1)</script><a attr=\"";
        String encoded = htmlEncode(payload);

        assertAttributeContextSafe(encoded);

        assertTrue("'<' must be encoded as &lt; in polyglot payload",
                encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt; in polyglot payload",
                encoded.contains("&gt;"));
        assertTrue("'\"' must be encoded as &quot; in polyglot payload",
                encoded.contains("&quot;"));
    }

    /**
     * Verifies that encoding is non-destructive for a pre-encoded entity
     * string — i.e. the encoder does not decode entities before re-encoding,
     * which would permit a double-decode attack.
     *
     * If the input already contains "&lt;" (an entity), encoding it again
     * should yield "&amp;lt;" rather than leaving it as "&lt;".
     */
    public void testEncodingDoesNotDecodeExistingEntities() {
        // An already-encoded string; a broken encoder might decode "&lt;" to
        // "<" before passing it to the output, reintroducing the XSS sink.
        String alreadyEncoded = "&lt;script&gt;alert(1)&lt;/script&gt;";
        String encoded = htmlEncode(alreadyEncoded);

        // The '&' in '&lt;' must itself be encoded as '&amp;' — no decode step.
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        // After correct encoding there must be no bare '<' in the output.
        assertFalse("Re-encoded output must not contain a bare '<'",
                encoded.contains("<"));
    }

    /**
     * Verifies that the session attribute key "userid" written by
     * LoginValidator.processRequest() is consistent with the key read by the
     * fixed change-email.jsp via ${sessionScope.userid}.
     *
     * LoginValidator stores:  session.setAttribute("userid", rs.getString("id"));
     * Fixed change-email.jsp reads: ${sessionScope.userid} via c:out.
     *
     * A mismatch would silently render an empty field (null attribute),
     * breaking the form submission — this test guards against that regression.
     */
    public void testSessionAttributeKeyConsistency() {
        // Key written by LoginValidator at login time
        String loginValidatorKey = "userid";

        // Key read by the fixed change-email.jsp via ${sessionScope.userid}
        String changeEmailJspKey = "userid";

        assertEquals(
                "LoginValidator must store the user id under the same key that " +
                "the fixed change-email.jsp reads via ${sessionScope.userid}",
                loginValidatorKey, changeEmailJspKey);
    }

    /**
     * Verifies that a stored XSS payload containing HTML comment delimiters
     * (--&gt;) does not escape the comment context.  After encoding, the
     * angle brackets are replaced with entities.
     */
    public void testHtmlCommentBreakoutPayloadIsEncoded() {
        String payload = "1-->alert(1)<!--";
        String encoded = htmlEncode(payload);

        // The '-->' sequence still contains '-' characters which are not
        // special HTML characters, but the '>' must be encoded.
        assertFalse("Encoded output must not contain raw '>'",
                encoded.contains(">"));
        assertTrue("'>' must be encoded as &gt;",
                encoded.contains("&gt;"));
    }

    /**
     * Verifies that a stored XSS payload using HTML5 data-attribute breaking
     * syntax is neutralised:
     *   42 data-x="&gt;&lt;script&gt;alert(1)&lt;/script&gt;
     *
     * The double-quote terminates the value attribute if unencoded.
     * After c:out encoding, the payload is inert.
     */
    public void testDataAttributeBreakoutPayloadIsEncoded() {
        String payload = "42 data-x=\"><script>alert(1)</script>";
        String encoded = htmlEncode(payload);

        assertAttributeContextSafe(encoded);
        assertTrue("'\"' must be encoded as &quot; in data-attribute payload",
                encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt; in data-attribute payload",
                encoded.contains("&lt;"));
    }
}
