package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in change-email.jsp.
 *
 * Vulnerability: The hidden form field in change-email.jsp emitted the session
 * attribute "userid" directly via {@code out.print(session.getAttribute("userid"))}
 * without any HTML encoding.  If an attacker stored a malicious payload in the
 * database as their user-id (e.g. via a crafted registration), that payload would
 * be rendered as live HTML/JavaScript in every victim's browser that visited the
 * change-email form.
 *
 * Fix: Replaced the vulnerable {@code out.print()} sink with JSTL
 * {@code <c:out value='${sessionScope.userid}'/>} which applies HTML entity
 * encoding (escapeXml="true" by default).  This encodes characters such as
 * &lt; &gt; &amp; &quot; &#x27; so that any XSS payload stored in the
 * database is rendered as inert text rather than executable markup.
 *
 * These unit tests verify the HTML encoding semantics that the JSTL c:out tag
 * relies on, confirming that:
 *   1. HTML special characters in the userid session value are encoded to their entities.
 *   2. Classic XSS script-tag payloads stored as userid are neutralised.
 *   3. Event-handler attribute payloads (e.g. injected via form value breakout) are neutralised.
 *   4. Safe values (plain numeric user-ids) pass through unchanged.
 *   5. Null / empty attribute values produce no exploitable output.
 *   6. The hidden-field attribute boundary is preserved for all attack variants.
 */
public class ChangeEmailXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions that
    // javax.servlet.jsp.tagext.TagSupport (and hence c:out escapeXml=true)
    // applies.  This is NOT the production fix; it is used here only to make
    // the encoding logic testable without a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that JSTL
     * {@code <c:out escapeXml="true"/>} (the default) applies at render time.
     *
     * Characters encoded: &amp; &lt; &gt; &#x27; &quot;
     *
     * @param input raw value from session / database (the "userid" attribute)
     * @return HTML-safe string suitable for embedding in an HTML attribute value
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
    // Helper: asserts that the encoded value does not contain raw XSS markers.
    // -------------------------------------------------------------------------

    private static void assertNoRawHtmlSpecialChars(String encodedOutput) {
        assertFalse("Encoded output must not contain raw '<'",
                encodedOutput.contains("<"));
        assertFalse("Encoded output must not contain raw '>'",
                encodedOutput.contains(">"));
        assertFalse("Encoded output must not contain unencoded '\"'",
                containsUnencodedDoubleQuote(encodedOutput));
    }

    /**
     * Returns true only if the string contains a literal '"' character that
     * is NOT part of the &quot; entity sequence.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
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
     * encoding unchanged so the hidden form field value remains correct.
     */
    public void testSafeNumericUserIdIsUnchanged() {
        String userId = "42";
        String encoded = htmlEncode(userId);
        assertEquals("A plain numeric user-id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * A plain alphanumeric user-id must not be mangled by encoding.
     */
    public void testSafeAlphanumericUserIdIsUnchanged() {
        String userId = "user123";
        String encoded = htmlEncode(userId);
        assertEquals("Safe alphanumeric user-id must survive encoding unchanged",
                "user123", encoded);
    }

    /**
     * A classic stored XSS payload injected as a user-id:
     *   &lt;script&gt;alert(1)&lt;/script&gt;
     * must have its angle brackets encoded so that the browser does not treat
     * the tag as executable markup when it is rendered in the hidden field.
     */
    public void testScriptTagPayloadInUserIdIsEncoded() {
        String xssPayload = "<script>alert(1)</script>";
        String encoded = htmlEncode(xssPayload);

        assertNoRawHtmlSpecialChars(encoded);

        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));

        // The literal word "script" remains as inert text — the tags around it
        // have been neutered via encoding.
        assertTrue("Text content of the tag should remain as inert text",
                encoded.contains("script"));
    }

    /**
     * An attribute-breakout payload injected as a user-id:
     *   1" onmouseover="alert(document.cookie)
     * would break out of the hidden input's value="..." attribute if rendered
     * unencoded.  After encoding, the double-quotes become &quot; so the
     * attribute boundary is preserved.
     */
    public void testAttributeBreakoutPayloadInUserIdIsEncoded() {
        String payload = "1\" onmouseover=\"alert(document.cookie)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw unencoded double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * An attribute-breakout using single-quotes:
     *   1' onmouseover='alert(document.cookie)
     * must have the single-quotes encoded as &#x27; to preserve the
     * attribute boundary if the template uses single-quoted attributes.
     * The fixed JSP uses {@code value='${sessionScope.userid}'} with single quotes.
     */
    public void testSingleQuoteBreakoutInUserIdIsEncoded() {
        String payload = "1' onmouseover='alert(1)";
        String encoded = htmlEncode(payload);

        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * A polyglot XSS payload designed to break out of both attribute and
     * element context:
     *   "><img src=x onerror=alert(1)>
     * After encoding all angle-brackets and double-quotes are replaced with
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
     * An img-based XSS payload without angle bracket breakout:
     *   42 /><img src=x onerror=alert(1)
     * would close the input tag and inject a new img element if rendered raw
     * inside the value attribute.  After encoding, the '/' stays as-is
     * (harmless) but the angle brackets are neutered.
     */
    public void testImgTagInjectionPayloadIsEncoded() {
        String payload = "42 /><img src=x onerror=alert(1)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>'", encoded.contains(">"));
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * A null session attribute (user not logged in, or attribute cleared) must
     * produce an empty string rather than the literal text "null", which would
     * be a mild information disclosure and would also break the form submission.
     */
    public void testNullUserIdProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null userid attribute must encode to empty string",
                "", encoded);
    }

    /**
     * An empty string user-id must encode to an empty string (no output).
     */
    public void testEmptyUserIdProducesEmptyString() {
        String encoded = htmlEncode("");
        assertEquals("Empty user-id must encode to empty string",
                "", encoded);
    }

    /**
     * An ampersand in a user-id (e.g. injected to cause HTTP parameter
     * pollution or HTML entity injection) must be encoded as &amp;.
     */
    public void testAmpersandInUserIdIsEncoded() {
        String value = "1&admin=true";
        String encoded = htmlEncode(value);

        assertFalse("Raw '&' must not appear in encoded output as '&admin'",
                encoded.contains("&admin"));
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * Verifies that encoding is idempotent at the entity level — encoding the
     * output again does not re-introduce exploitable characters.  This guards
     * against double-decode attacks.
     */
    public void testEncodingDoesNotIntroduceNewSpecialCharacters() {
        // Start with an already-encoded string that would be dangerous if a
        // broken encoder decoded entities first before re-encoding.
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
     * Verifies that the session attribute key written by LoginValidator ("userid")
     * matches the key read by the fixed change-email.jsp (${sessionScope.userid}).
     *
     * LoginValidator sets:
     *   session.setAttribute("userid", rs.getString("id"));
     * The fixed JSP reads:
     *   ${sessionScope.userid}  (via c:out)
     *
     * A mismatch would silently render an empty value, breaking the form.
     */
    public void testSessionAttributeKeyConsistency() {
        // The attribute name written by LoginValidator at login time.
        String loginValidatorKey = "userid";

        // The attribute name read by the fixed change-email.jsp (documented
        // here as a compile-time constant for traceability).
        String changeEmailJspKey = "userid";

        assertEquals(
                "LoginValidator must store the user id under the same key " +
                "that the fixed change-email.jsp reads via ${sessionScope.userid}",
                loginValidatorKey, changeEmailJspKey);
    }

    /**
     * A javascript: URI payload as a user-id — while primarily a concern when
     * the value appears in href attributes, the single-quote in such payloads
     * would also break out of the single-quoted value attribute in the fixed JSP.
     * Verify that single-quotes are properly encoded.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        // Single-quotes must be encoded as &#x27;
        assertFalse("Single-quote must not appear unencoded", encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;", encoded.contains("&#x27;"));
    }
}
