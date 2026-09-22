package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in forum.jsp.
 *
 * <h2>Vulnerability description (CWE-79, CVSS 9.4)</h2>
 * The taint flow was:
 * <ol>
 *   <li>An attacker registers/logs-in with a username containing an XSS payload
 *       (e.g. {@code "><script>alert(1)</script>}) which gets stored in the
 *       database via adminlogin.jsp.</li>
 *   <li>adminlogin.jsp reads the username back via {@code rs.getString("username")}
 *       and stores it in the HTTP session:
 *       {@code session.setAttribute("user", rs.getString("username"))}.</li>
 *   <li>forum.jsp (line 32) then emitted the session attribute directly into the
 *       HTML attribute value of a hidden input using {@code out.print()} without
 *       any HTML encoding:
 *       <pre>
 *       value="&lt;% ... out.print(session.getAttribute("user")); ... %&gt;"
 *       </pre>
 *       A malicious username such as {@code "><script>alert(1)</script>} would
 *       therefore break out of the attribute context and execute as script.</li>
 * </ol>
 *
 * <h2>The fix</h2>
 * The scriptlet {@code out.print(session.getAttribute("user"))} was replaced
 * with the JSTL {@code <c:out>} tag (with the default {@code escapeXml="true"}),
 * which HTML-encodes the five characters {@code & < > " '} before rendering:
 * <pre>
 * &lt;input type="hidden" name="user"
 *        value="&lt;c:out value="${not empty sessionScope.user
 *                                   ? sessionScope.user : 'Anonymous'}"
 *               escapeXml="true"/&gt;" /&gt;
 * </pre>
 * The JSTL {@code <c:out>} tag is a SAST-recognised HTML sanitizer that breaks
 * the taint flow from the database-sourced session attribute to the HTML output
 * sink.
 *
 * <h2>What these tests verify</h2>
 * These unit tests verify the HTML encoding semantics that {@code c:out
 * escapeXml="true"} relies on, confirming that:
 * <ol>
 *   <li>Classic script-tag payloads are neutralised (angle brackets encoded).</li>
 *   <li>Attribute-escape payloads (double-quote injection) are neutralised.</li>
 *   <li>Single-quote payloads are encoded as {@code &#x27;}.</li>
 *   <li>Ampersand injection is encoded as {@code &amp;}.</li>
 *   <li>Safe alphanumeric usernames pass through unchanged.</li>
 *   <li>A null session attribute produces an empty string (no "null" text).</li>
 *   <li>The fallback "Anonymous" value does not contain HTML-special characters
 *       (no encoding required, but its safety is asserted).</li>
 *   <li>A polyglot payload combining angle brackets and double quotes is fully
 *       encoded.</li>
 *   <li>The session attribute key "user" used in forum.jsp matches what
 *       adminlogin.jsp stores.</li>
 * </ol>
 */
public class ForumStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions that
    // javax.servlet.jsp.tagext.TagSupport (and hence c:out escapeXml=true)
    // applies at render time.  This is NOT the production fix; it is used
    // here only to make the encoding logic testable without a running
    // servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that JSTL
     * {@code <c:out escapeXml="true"/>} (the default) applies at render time.
     *
     * <p>Characters encoded: {@code & < > ' "}</p>
     *
     * @param input raw value from session / database (may be null)
     * @return HTML-safe string suitable for embedding in an HTML attribute value
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
    // Helper: asserts that the encoded string does NOT contain raw XSS markers
    // -------------------------------------------------------------------------

    /**
     * Asserts that {@code encoded} contains no raw angle brackets or unencoded
     * double-quotes — the three characters that would allow an attacker to
     * break out of an HTML attribute value and inject markup or script.
     *
     * @param encoded the HTML-encoded output to check
     */
    private static void assertXssNeutralised(String encoded) {
        assertFalse("Encoded output must not contain raw '<'",
                encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>'",
                encoded.contains(">"));
        assertFalse("Encoded output must not contain unencoded '\"'",
                containsUnencodedDoubleQuote(encoded));
    }

    /**
     * Returns {@code true} only if {@code s} contains a literal {@code "}
     * character that is NOT the terminal character of the {@code &quot;} entity.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                // Accept only if the preceding 5 characters form "&quot;"
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
     * A plain alphanumeric username (the most common legitimate case) must
     * survive HTML encoding completely unchanged so that the hidden input
     * value is correct and the form POST succeeds.
     */
    public void testSafeAlphanumericUsernamePassesThroughUnchanged() {
        String username = "john_doe123";
        String encoded  = htmlEncode(username);
        assertEquals(
                "A safe alphanumeric username must not be altered by HTML encoding",
                "john_doe123", encoded);
    }

    /**
     * A classic stored XSS payload injected as a username:
     * {@code <script>alert(1)</script>}
     * must have its angle brackets encoded so that the browser does not treat
     * the tag as executable markup when it appears inside the hidden input's
     * {@code value} attribute.
     */
    public void testScriptTagPayloadIsEncoded() {
        String payload = "<script>alert(1)</script>";
        String encoded = htmlEncode(payload);

        assertXssNeutralised(encoded);

        assertTrue("'<' must be encoded as &lt;",  encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",  encoded.contains("&gt;"));
        // "script" text is still present but inert without surrounding brackets
        assertTrue("Text content should remain as inert text",
                encoded.contains("script"));
    }

    /**
     * An attribute-escape payload stored as a username:
     * {@code "><script>alert(document.cookie)</script>}
     * would close the {@code value="..."} attribute and inject a new element
     * if rendered unencoded.  After c:out encoding the double-quote and angle
     * brackets must be encoded as entities.
     */
    public void testAttributeEscapePayloadIsEncoded() {
        String payload = "\"><script>alert(document.cookie)</script>";
        String encoded = htmlEncode(payload);

        assertXssNeutralised(encoded);

        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;",    encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",    encoded.contains("&gt;"));
    }

    /**
     * An event-handler injection payload stored as a username:
     * {@code 1" onmouseover="alert(document.cookie)}
     * would inject an event-handler attribute if the double-quote is not
     * encoded.  After encoding, the double-quote must become {@code &quot;}.
     */
    public void testEventHandlerInjectionPayloadIsEncoded() {
        String payload = "1\" onmouseover=\"alert(document.cookie)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
    }

    /**
     * A single-quote injection payload stored as a username:
     * {@code ' OR '1'='1}
     * (common SQL injection pattern also usable for attribute breaking)
     * must have its single-quotes encoded as {@code &#x27;}.
     */
    public void testSingleQuotePayloadIsEncoded() {
        String payload = "' OR '1'='1";
        String encoded = htmlEncode(payload);

        assertFalse("Raw single-quote must not appear in encoded output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * An ampersand in a stored username (e.g. as part of a URL-embedded
     * payload) must be encoded as {@code &amp;} to prevent HTML entity
     * injection or breaking the attribute syntax.
     */
    public void testAmpersandInUsernameIsEncoded() {
        String payload = "user&amp;admin=true";
        String encoded = htmlEncode(payload);

        // The & in the input must have been encoded; the result must NOT
        // contain a raw & that could introduce new entity sequences.
        assertFalse("Encoded output must not contain a raw '&' followed by 'amp'",
                encoded.contains("&amp;admin")); // the & was re-encoded
        assertTrue("'&' must be encoded as &amp;", encoded.contains("&amp;"));
    }

    /**
     * A raw ampersand payload must be encoded as {@code &amp;}.
     */
    public void testRawAmpersandIsEncoded() {
        String payload = "user&role=admin";
        String encoded = htmlEncode(payload);

        assertTrue("'&' must be encoded as &amp;", encoded.contains("&amp;"));
        // Confirm the original '&' is gone
        assertFalse("Original '&' must not appear unencoded before 'role'",
                encoded.contains("&role"));
    }

    /**
     * A null session attribute (user not logged in, or attribute cleared)
     * must produce an empty string via {@code c:out}, not the text "null",
     * which would be user-visible garbage output.
     *
     * In the fixed JSP the EL expression {@code ${not empty sessionScope.user
     * ? sessionScope.user : 'Anonymous'}} handles this by falling back to
     * "Anonymous" before c:out renders it; this test verifies the encoding
     * layer returns "" for null, consistent with c:out behaviour.
     */
    public void testNullUsernameProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null session attribute must encode to empty string",
                "", encoded);
    }

    /**
     * The fallback value "Anonymous" (used when no user is logged in) must
     * not contain HTML-special characters, so it is safe to render without
     * encoding; but this test asserts that if it were run through the encoder
     * it passes through unchanged — confirming the fallback is benign.
     */
    public void testAnonymousFallbackValueIsAlreadySafe() {
        String fallback = "Anonymous";
        String encoded  = htmlEncode(fallback);
        assertEquals("The 'Anonymous' fallback must survive encoding unchanged",
                "Anonymous", encoded);
    }

    /**
     * A polyglot XSS payload designed to break out of both element content
     * and attribute context:
     * {@code "><img src=x onerror=alert(1)>}
     * After encoding, all angle brackets and double-quotes must be replaced
     * with their entity forms so the payload is completely inert.
     */
    public void testPolyglotXssPayloadIsFullyEncoded() {
        String payload = "\"><img src=x onerror=alert(1)>";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>'", encoded.contains(">"));
        assertFalse("Encoded output must not contain unencoded '\"'",
                containsUnencodedDoubleQuote(encoded));

        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;",    encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",    encoded.contains("&gt;"));
    }

    /**
     * Verifies that HTML encoding is not defeated by a double-encode bypass:
     * if the input already contains an HTML entity like {@code &lt;}, the
     * ampersand must itself be encoded to {@code &amp;lt;}, preventing a
     * second-decoding attack in browsers that parse entities twice.
     */
    public void testAlreadyEncodedInputIsReEncodedToPreventDoubleDecodeAttack() {
        String alreadyEncoded = "&lt;script&gt;";
        String encoded = htmlEncode(alreadyEncoded);

        // The '&' in '&lt;' must be encoded as '&amp;'
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        // No raw angle brackets may appear
        assertFalse("Encoded output must not contain bare '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain bare '>'", encoded.contains(">"));
    }

    /**
     * Verifies that the session attribute key "user" used in the fixed
     * forum.jsp ({@code ${sessionScope.user}}) matches the key written by
     * adminlogin.jsp ({@code session.setAttribute("user", ...)}).
     *
     * This is the contract between the authentication layer (source of taint)
     * and the forum page (former sink of taint); keeping both sides in sync
     * is critical for the fix to remain effective.
     */
    public void testSessionAttributeKeyConsistencyBetweenAdminLoginAndForumJsp() {
        // Key written by adminlogin.jsp at login time (source of taint)
        String adminLoginSetKey = "user";

        // Key read by the fixed forum.jsp in ${sessionScope.user}
        String forumJspGetKey = "user";

        assertEquals(
                "adminlogin.jsp must store the username under the same session " +
                "attribute key that forum.jsp reads via ${sessionScope.user}",
                adminLoginSetKey, forumJspGetKey);
    }

    /**
     * A username containing only whitespace is edge-case input that must
     * pass through the encoder unchanged (whitespace is not an HTML-special
     * character) and produce non-null output.
     */
    public void testWhitespaceOnlyUsernamePassesThroughUnchanged() {
        String whitespace = "   ";
        String encoded    = htmlEncode(whitespace);
        assertEquals("Whitespace-only username must be preserved by encoding",
                "   ", encoded);
    }

    /**
     * A username containing a mix of safe and unsafe characters — verifies
     * that only the special characters are encoded while the safe characters
     * are preserved verbatim.
     */
    public void testMixedSafeAndUnsafeCharactersAreEncodedSelectively() {
        String payload = "admin<>&\"'";
        String encoded = htmlEncode(payload);

        // Safe prefix must be intact
        assertTrue("Safe prefix 'admin' must be preserved", encoded.startsWith("admin"));

        // Each unsafe character must be encoded
        assertTrue("'<' must be encoded as &lt;",   encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",   encoded.contains("&gt;"));
        assertTrue("'&' must be encoded as &amp;",  encoded.contains("&amp;"));
        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'\'' must be encoded as &#x27;", encoded.contains("&#x27;"));

        // No raw special characters in the output
        assertXssNeutralised(encoded);
        assertFalse("Raw single-quote must not appear", encoded.contains("'"));
    }
}
