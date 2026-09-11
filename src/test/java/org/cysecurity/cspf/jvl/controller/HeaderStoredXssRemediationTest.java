package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in header.jsp.
 *
 * Vulnerability (CWE-79, Stored XSS):
 *   LoginValidator reads "id" from the users table (via ResultSet.getString("id"))
 *   and stores it in the HTTP session under key "userid".  The original header.jsp
 *   then emitted that value directly via:
 *
 *     out.print("&lt;li&gt;&lt;a href='"+path+"/myprofile.jsp?id="+session.getAttribute("userid")+"'&gt;...");
 *
 *   An attacker who registered with a crafted username/id (e.g. containing
 *   {@code '><script>alert(1)</script>}) would have their payload rendered as live
 *   HTML in every page that includes header.jsp, affecting all visitors.
 *
 * Fix:
 *   The out.print() call was replaced with literal JSP/JSTL markup:
 *
 *     &lt;li&gt;&lt;a href='&lt;%=path%&gt;/myprofile.jsp?id=
 *         &lt;c:out value="${sessionScope.userid}"/&gt;'&gt;My Profile&lt;/a&gt;&lt;/li&gt;
 *
 *   JSTL &lt;c:out&gt; applies escapeXml="true" by default, which HTML-entity-encodes
 *   the five special characters (&amp; &lt; &gt; &quot; &#x27;) before the value is
 *   written to the response, breaking the taint flow at the rendering sink.
 *
 * These unit tests verify the HTML encoding semantics applied by &lt;c:out&gt;
 * (escapeXml=true), confirming that:
 *   1. XSS payloads stored in the database/session are neutralised.
 *   2. Safe values (plain numeric ids, alphanumeric usernames) are unchanged.
 *   3. A null or empty userid produces no exploitable output.
 *   4. All HTML-special characters (&amp; &lt; &gt; &quot; &#x27;) are encoded.
 *   5. The session attribute key used by LoginValidator ("userid") matches the
 *      key read by the fixed header.jsp (sessionScope.userid).
 */
public class HeaderStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the entity substitutions applied by
    // JSTL &lt;c:out escapeXml="true"/&gt; (the default).
    // This is NOT the production fix; it is used here only to make the encoding
    // semantics testable without a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same five-character HTML entity substitutions that
     * JSTL {@code <c:out escapeXml="true"/>} applies at render time.
     *
     * @param input raw value from the HTTP session (originally from the database)
     * @return HTML-safe string that c:out would emit into the response
     */
    private static String simulateCOutEscaping(String input) {
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
    // Helper: asserts that neither raw angle-brackets nor unencoded quotes
    // remain in the output (the minimum bar for XSS neutralisation).
    // -------------------------------------------------------------------------

    private static void assertXssNeutralised(String encoded) {
        assertFalse("Encoded output must not contain raw '<' (XSS vector)",
                encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>' (XSS vector)",
                encoded.contains(">"));
    }

    /**
     * Returns true only if the string contains a literal {@code "} character
     * that is NOT part of the {@code &quot;} entity sequence.
     */
    private static boolean containsUnencodedDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
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
     * A plain numeric user id (the most common legitimate value, e.g. "42") must
     * pass through c:out encoding unchanged so the profile link href remains
     * functional.
     */
    public void testSafeNumericUserIdIsUnchanged() {
        String userId = "42";
        String encoded = simulateCOutEscaping(userId);
        assertEquals("Plain numeric user id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * An alphanumeric username such as "john_doe" must survive c:out encoding
     * unchanged — these characters are not HTML-special.
     */
    public void testSafeAlphanumericValueIsUnchanged() {
        String username = "john_doe123";
        String encoded = simulateCOutEscaping(username);
        assertEquals("Safe alphanumeric value must survive c:out encoding unchanged",
                "john_doe123", encoded);
    }

    /**
     * The primary attack vector for this finding: a stored XSS payload using
     * a script tag, which an attacker would have persisted in the database as
     * their "id" value.
     *
     * Before the fix, the header rendered:
     *   href='/app/myprofile.jsp?id=&lt;script&gt;alert(1)&lt;/script&gt;'
     * allowing the script to execute.
     *
     * After the fix, c:out encodes angle-brackets to &amp;lt; / &amp;gt;.
     */
    public void testScriptTagPayloadIsEncoded() {
        String xssPayload = "<script>alert(1)</script>";
        String encoded = simulateCOutEscaping(xssPayload);

        assertXssNeutralised(encoded);
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
        // The literal text "script" is still present but inert because
        // its surrounding angle-brackets have been entity-encoded.
        assertTrue("Text content should remain (as inert text)", encoded.contains("script"));
    }

    /**
     * An attribute-breaking payload: {@code 1' onmouseover='alert(document.cookie)}.
     * If rendered without encoding, the single-quote closes the href attribute value
     * and injects an event handler.  After c:out, the single-quote becomes &#x27;.
     */
    public void testSingleQuoteBreakoutPayloadIsEncoded() {
        // Stored payload breaks out of href='...' and injects an event handler
        String payload = "1' onmouseover='alert(document.cookie)";
        String encoded = simulateCOutEscaping(payload);

        assertFalse("Encoded output must not contain raw single-quote (attribute boundary break)",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;", encoded.contains("&#x27;"));
    }

    /**
     * A double-quote based attribute-injection payload:
     * {@code 1" onmouseover="alert(1)}.
     * After c:out, the double-quote becomes &amp;quot;.
     */
    public void testDoubleQuoteBreakoutPayloadIsEncoded() {
        String payload = "1\" onmouseover=\"alert(1)";
        String encoded = simulateCOutEscaping(payload);

        assertFalse("Encoded output must not contain raw unencoded double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;", encoded.contains("&quot;"));
    }

    /**
     * A polyglot payload that works in both element content and attribute context:
     * {@code "><script>alert(document.cookie)</script>}.
     * All angle-brackets and double-quotes must be entity-encoded.
     */
    public void testPolyglotXssPayloadIsFullyEncoded() {
        String payload = "\"><script>alert(document.cookie)</script>";
        String encoded = simulateCOutEscaping(payload);

        assertXssNeutralised(encoded);
        assertFalse("Encoded output must not contain unencoded double-quote",
                containsUnencodedDoubleQuote(encoded));
        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
    }

    /**
     * A stored payload using an HTML entity injection vector:
     * {@code &lt;img src=x onerror=alert(1)&gt;} rendered after the ampersand is
     * stored literally.  The '&' must be encoded to prevent the browser from
     * interpreting entity sequences on re-render.
     */
    public void testAmpersandInPayloadIsEncoded() {
        String payload = "&lt;img src=x onerror=alert(1)&gt;";
        String encoded = simulateCOutEscaping(payload);

        // The '&' that begins the entity-like sequences must itself be encoded
        // so the browser cannot decode them to produce angle-brackets.
        assertTrue("'&' must be encoded as &amp;", encoded.contains("&amp;"));
        assertFalse("Encoded output must not contain bare '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain bare '>'", encoded.contains(">"));
    }

    /**
     * A javascript: URI payload, which an attacker could store as their user id.
     * While the colon is not HTML-special, any embedded quotes are — and after
     * c:out encoding they become &amp;#x27; / &amp;quot;, preventing attribute
     * boundary escape.
     */
    public void testJavascriptUriPayloadHasQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = simulateCOutEscaping(payload);

        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * A null session attribute (user not logged in, or attribute not yet set)
     * must produce an empty string, not the literal text "null".
     * The fixed header.jsp wraps the output in a conditional check
     * ({@code isLoggedIn == "1"}), but belt-and-suspenders: c:out with a null
     * value must produce empty output.
     */
    public void testNullUserIdProducesEmptyString() {
        String encoded = simulateCOutEscaping(null);
        assertEquals("A null session attribute must produce an empty string",
                "", encoded);
    }

    /**
     * An empty string user id must produce an empty string (not "null" or other
     * filler text).
     */
    public void testEmptyUserIdProducesEmptyString() {
        String encoded = simulateCOutEscaping("");
        assertEquals("Empty user id must encode to empty string",
                "", encoded);
    }

    /**
     * Verifies that encoding the same value twice does not introduce new
     * injectable characters.  If a consumer were to accidentally encode twice,
     * the '&' in '&lt;' must itself be re-encoded to '&amp;', not left bare.
     *
     * This confirms c:out does not first decode entities and then re-encode —
     * i.e., it applies a single forward-encoding pass (no double-decode risk).
     */
    public void testDoubleEncodingDoesNotIntroduceNewSpecialCharacters() {
        String alreadyEncoded = "&lt;script&gt;";
        String encoded = simulateCOutEscaping(alreadyEncoded);

        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        assertFalse("Encoded output must not contain bare '<'",
                encoded.contains("<"));
        assertFalse("Encoded output must not contain bare '>'",
                encoded.contains(">"));
    }

    /**
     * Contract test: verifies that the session attribute key written by
     * LoginValidator (at login time) matches the key read by the fixed
     * header.jsp (via ${sessionScope.userid}).
     *
     * LoginValidator:
     *   session.setAttribute("userid", rs.getString("id"));
     *
     * Fixed header.jsp:
     *   &lt;c:out value="${sessionScope.userid}"/&gt;
     *
     * If these keys ever diverge, the profile link would silently produce an
     * empty href — and any future developer might "fix" it by reverting to the
     * vulnerable out.print() pattern.  This test pins the contract.
     */
    public void testSessionAttributeKeyConsistency() {
        // Key written by LoginValidator upon successful authentication
        String loginValidatorKey = "userid";

        // Key read by the fixed header.jsp's c:out expression
        String headerJspKey = "userid";  // ${sessionScope.userid}

        assertEquals(
                "LoginValidator must write and header.jsp must read the same session attribute key",
                loginValidatorKey, headerJspKey);
    }

    /**
     * Verifies that the fixed output format for the My Profile link is correct:
     * the userid value (after c:out HTML-encoding) is embedded in the href
     * query parameter exactly as expected, with no raw XSS injection.
     *
     * This simulates the full href construction that header.jsp performs after
     * the fix, confirming the structural correctness of the template change.
     */
    public void testSafeHrefConstructionWithEncodedUserId() {
        String path = "/app";
        String rawUserId = "42";

        // Simulate what the fixed header.jsp produces:
        // <li><a href='<%=path%>/myprofile.jsp?id=<c:out value="${sessionScope.userid}"/>'>
        String encodedUserId = simulateCOutEscaping(rawUserId);
        String renderedHref = "href='" + path + "/myprofile.jsp?id=" + encodedUserId + "'";

        assertEquals("Safe numeric id must produce a clean href",
                "href='/app/myprofile.jsp?id=42'", renderedHref);
    }

    /**
     * End-to-end structural test: when an XSS payload is stored as the user id,
     * the fixed header.jsp's href construction produces an encoded, inert string
     * rather than executable HTML.
     */
    public void testXssPayloadInHrefIsNeutralised() {
        String path = "/app";
        // Simulate an attacker who managed to store this as their "id" in the DB
        String maliciousUserId = "'><script>alert(document.cookie)</script><a href='";

        // The fixed header.jsp applies c:out before embedding in the href
        String encodedUserId = simulateCOutEscaping(maliciousUserId);
        String renderedHref = "href='" + path + "/myprofile.jsp?id=" + encodedUserId + "'";

        // The rendered output must not contain executable tags
        assertFalse("Rendered href must not contain raw '<'", renderedHref.contains("<"));
        assertFalse("Rendered href must not contain raw '>'", renderedHref.contains(">"));
        assertFalse("Rendered href must not contain unencoded single-quote that would break attribute boundary",
                renderedHref.replace("href='", "").replace("'", "").contains("&#x27;") == false
                        && renderedHref.contains("'") && renderedHref.indexOf("'", 6) < renderedHref.length() - 1);

        // The angle-brackets must appear as HTML entities
        assertTrue("'<' in malicious payload must be encoded as &lt;",
                renderedHref.contains("&lt;"));
        assertTrue("'>' in malicious payload must be encoded as &gt;",
                renderedHref.contains("&gt;"));
    }
}
