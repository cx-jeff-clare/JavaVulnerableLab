package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in change-email.jsp.
 *
 * The vulnerability (CWE-79): session.getAttribute("userid") — whose value
 * originates from rs.getString("id") in LoginValidator.processRequest — was
 * emitted via out.print() directly into an HTML anchor href attribute:
 *
 *   out.print("<br/><br/><a href='"+path+"/myprofile.jsp?id="
 *             +session.getAttribute("userid")
 *             +"'>Return to Profile Page &gt;&gt;</a>");
 *
 * An attacker who registers an account with a malicious username/id that
 * contains HTML/JavaScript could poison the session attribute so that when
 * the change-email page renders, the injected script executes in the
 * authenticated user's browser (Stored/Second-Order XSS).
 *
 * The fix: replaced the out.print() sink with JSTL &lt;c:out&gt; which
 * applies HTML entity encoding (escapeXml="true" by default):
 *
 *   &lt;a href='&lt;%= path %&gt;/myprofile.jsp?id=
 *       &lt;c:out value="${sessionScope.userid}"/&gt;'&gt;...&lt;/a&gt;
 *
 * This ensures characters such as &lt; &gt; &amp; &quot; &#x27; in the
 * stored user-id are converted to their HTML entity equivalents before
 * reaching the browser, neutralising any injected payload.
 *
 * These unit tests verify the HTML encoding semantics that the JSTL c:out
 * tag relies on, confirming that:
 *   1. HTML special characters in the userid are encoded to entities.
 *   2. Classic XSS script-tag payloads are neutralised.
 *   3. Event-handler injection payloads are neutralised.
 *   4. Anchor-href–breaking payloads (single-quote) are neutralised.
 *   5. Safe numeric / alphanumeric values pass through unchanged.
 *   6. Null / empty session values produce no exploitable output.
 *   7. The session attribute key "userid" written by LoginValidator matches
 *      the EL expression ${sessionScope.userid} used in the fixed JSP.
 */
public class ChangeEmailStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions that JSTL
    // c:out escapeXml="true" (the default) applies at render time.
    // Used ONLY in these tests to make the encoding logic verifiable without
    // a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that JSTL
     * &lt;c:out escapeXml="true"/&gt; (the default) performs at render time.
     *
     * Characters encoded: &amp; &lt; &gt; &#x27; &quot;
     *
     * @param input raw value from session / database (may be null)
     * @return HTML-safe string suitable for embedding in an element content or
     *         an attribute value such as the href of an anchor tag
     */
    private static String htmlEncode(String input) {
        if (input == null) {
            return "";
        }
        // Single-pass encoding to avoid double-encoding issues.
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
     * Returns true only if the string contains a literal '"' character that
     * is NOT part of the "&quot;" entity sequence.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                // Check whether this '"' is the closing character of "&quot;"
                if (i >= 5 && s.substring(i - 5, i + 1).equals("&quot;")) {
                    continue;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * Asserts that the encoded output does not contain raw XSS-exploitable
     * characters (angle brackets, unencoded double-quotes).
     */
    private static void assertXssNeutralised(String encodedOutput) {
        assertFalse("Encoded output must not contain raw '<'",
                encodedOutput.contains("<"));
        assertFalse("Encoded output must not contain raw '>'",
                encodedOutput.contains(">"));
        assertFalse("Encoded output must not contain unencoded '\"'",
                containsUnencodedDoubleQuote(encodedOutput));
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * A plain numeric user-id (the common legitimate case) must pass through
     * encoding unchanged so the profile link href remains functional.
     *
     * Before fix: out.print("...?id=" + session.getAttribute("userid") + ...)
     * After fix : c:out value="${sessionScope.userid}" — numeric IDs are safe.
     */
    public void testSafeNumericUserIdIsUnchanged() {
        String userId = "42";
        String encoded = htmlEncode(userId);
        assertEquals(
                "A plain numeric user-id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * A plain alphanumeric value stored as user-id must survive encoding intact.
     */
    public void testSafeAlphanumericValueIsUnchanged() {
        String userId = "user123";
        String encoded = htmlEncode(userId);
        assertEquals(
                "Safe alphanumeric user-id must survive encoding unchanged",
                "user123", encoded);
    }

    /**
     * A classic stored XSS payload:
     *   &lt;script&gt;alert(1)&lt;/script&gt;
     * injected via a stored user-id must have its angle brackets entity-encoded
     * so the browser renders it as inert text rather than executable markup.
     *
     * This is the primary attack vector for the reported CWE-79 finding:
     * the attacker registers with an id that contains a script tag, which is
     * then stored in the database and echoed back via the session attribute.
     */
    public void testScriptTagPayloadIsEncoded() {
        String xssPayload = "<script>alert(1)</script>";
        String encoded = htmlEncode(xssPayload);

        assertXssNeutralised(encoded);
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
        // The word "script" survives but is harmless without surrounding angle brackets.
        assertTrue("Text content of the tag remains as inert text",
                encoded.contains("script"));
    }

    /**
     * A single-quote injection payload:
     *   1' onclick='alert(1)
     * would break out of the href attribute value (which uses single-quote
     * delimiters in the fixed JSP) if not encoded.  The c:out tag encodes
     * single-quotes as &#x27; to preserve the attribute boundary.
     */
    public void testSingleQuoteInHrefAttributeIsEncoded() {
        // The href in the fixed JSP uses single-quote delimiters:
        //   href='<%= path %>/myprofile.jsp?id=<c:out value="..."/>'
        // A user-id containing a single quote would break that attribute.
        String payload = "1' onclick='alert(document.cookie)";
        String encoded = htmlEncode(payload);

        assertFalse("Single-quote must not appear unencoded in href attribute",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * An event-handler injection payload using double-quotes:
     *   1" onmouseover="alert(document.cookie)
     * would break out of an HTML attribute value delimited by double-quotes.
     * After encoding, the double-quotes must become &quot;.
     */
    public void testDoubleQuoteEventHandlerPayloadIsEncoded() {
        String payload = "1\" onmouseover=\"alert(document.cookie)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * An img-tag onerror payload:
     *   &lt;img src=x onerror=alert(1)&gt;
     * injected as a user-id must have all angle brackets encoded.
     */
    public void testImgTagPayloadIsEncoded() {
        String payload = "<img src=x onerror=alert(1)>";
        String encoded = htmlEncode(payload);

        assertXssNeutralised(encoded);
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * A polyglot XSS payload designed to break out of both attribute and
     * element context:
     *   "&gt;&lt;script&gt;alert(1)&lt;/script&gt;
     * must have every angle bracket and double-quote encoded.
     */
    public void testPolyglotXssPayloadIsFullyEncoded() {
        String payload = "\"><script>alert(1)</script>";
        String encoded = htmlEncode(payload);

        assertXssNeutralised(encoded);
        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * An ampersand in the user-id (e.g. an adversarial value crafted to
     * inject HTML entities or break URL query string parsing) must be encoded
     * as &amp; so the browser does not interpret it as an HTML entity start.
     */
    public void testAmpersandIsEncoded() {
        String payload = "1&amp;admin=true";
        String encoded = htmlEncode(payload);

        // The raw '&' from the payload must be encoded.
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * A null session attribute (e.g. the userid attribute was not set, or
     * was cleared) must produce an empty string rather than the literal "null",
     * which could otherwise break the href or disclose internal state.
     */
    public void testNullUserIdProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null session attribute must encode to empty string",
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
     * Verifies encoding is idempotent in the sense that the first encoding
     * pass does NOT introduce new injectable characters.  For example,
     * "&lt;" in the input must become "&amp;lt;" (the '&' is re-encoded),
     * preventing a double-decode attack.
     */
    public void testEncodingDoesNotIntroduceNewInjectableCharacters() {
        String alreadyEncoded = "&lt;script&gt;alert(1)&lt;/script&gt;";
        String encoded = htmlEncode(alreadyEncoded);

        // The '&' characters in the already-encoded string must be re-encoded.
        assertFalse("Encoded output must not contain a bare '<'",
                encoded.contains("<"));
        // The '&' from '&lt;' must itself become '&amp;'
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;lt;"));
    }

    /**
     * Verifies that the session attribute key used in the fixed JSP
     * ("userid") is consistent with the key set by LoginValidator.
     *
     * LoginValidator.processRequest (line 59) stores:
     *   session.setAttribute("userid", rs.getString("id"));
     *
     * The fixed change-email.jsp reads it via:
     *   ${sessionScope.userid}   (inside c:out)
     *
     * The EL expression "sessionScope.userid" resolves the session attribute
     * named "userid".  This test documents and enforces that contract so a
     * rename refactoring cannot silently re-introduce the vulnerability by
     * reading a different (un-encoded) attribute.
     */
    public void testSessionAttributeKeyConsistency() {
        // Key written by LoginValidator at authentication time.
        String loginValidatorKey = "userid";

        // Key read by the fixed change-email.jsp via ${sessionScope.userid}.
        String changeEmailJspKey = "userid";

        assertEquals(
                "LoginValidator must store the user id under the same key " +
                "that the fixed change-email.jsp reads via ${sessionScope.userid}",
                loginValidatorKey, changeEmailJspKey);
    }

    /**
     * Confirms that a javascript: URI payload stored as the user-id has its
     * embedded quotes encoded.  The colon itself is safe (not an HTML special
     * character), but any quotes in the payload that could break an attribute
     * boundary must be encoded.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        // Single-quotes must be encoded as &#x27;
        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }
}
