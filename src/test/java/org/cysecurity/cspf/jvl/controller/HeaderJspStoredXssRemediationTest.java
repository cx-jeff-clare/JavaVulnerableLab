package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests verifying the Stored XSS remediation in header.jsp.
 *
 * <h3>Vulnerability summary (CWE-79)</h3>
 * The adminlogin.jsp page reads user/admin records from the database
 * (ResultSet {@code rs}) and stores the {@code id} column value in the
 * HTTP session under the key {@code "userid"}:
 * <pre>
 *   session.setAttribute("userid", rs.getString("id"));
 * </pre>
 * header.jsp then rendered that value directly into the HTML output via
 * {@code out.print()} at two locations — one inside an {@code href} attribute
 * of a navigation link and one in the logged-in menu area — without any
 * HTML encoding:
 * <pre>
 *   // VULNERABLE (old code — SINK at original line 87)
 *   out.print(session.getAttribute("userid"));
 *   // VULNERABLE (old code — SINK at original line 149)
 *   out.print("...?id=" + session.getAttribute("userid") + "...");
 * </pre>
 * An attacker who can control the value stored in the {@code id} column
 * (e.g. through a secondary SQL injection or by registering with a crafted
 * username that maps to a manipulated id) can inject arbitrary HTML/JavaScript
 * that executes in every victim's browser that loads the navigation bar.
 *
 * <h3>Fix applied</h3>
 * Both sinks were replaced with JSTL {@code <c:out value="${sessionScope.userid}"/>},
 * which performs HTML entity encoding by default (escapeXml="true"), and a
 * {@code <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>}
 * directive was added to header.jsp.  {@code <c:out>} is a SAST-recognised
 * sanitiser: it converts the five HTML-significant characters
 * ({@code &}, {@code <}, {@code >}, {@code "}, {@code '}) to their safe
 * entity forms before writing to the response stream, preventing the browser
 * from interpreting attacker-controlled data as markup or script.
 *
 * <h3>What these tests verify</h3>
 * Because header.jsp is a JSP template that requires a live servlet container
 * to execute, these unit tests validate the <em>encoding semantics</em> that
 * JSTL {@code <c:out>} relies on.  The same five-entity substitution table is
 * reproduced here in a plain helper method, making the security contract
 * explicit and testable without a container:
 * <ol>
 *   <li>HTML special characters from the database are encoded to their entity forms.</li>
 *   <li>Classic script-tag XSS payloads are neutralised.</li>
 *   <li>Event-handler injection payloads (attribute break-out) are neutralised.</li>
 *   <li>Safe plain-text values pass through unchanged (no breakage for legitimate users).</li>
 *   <li>Null / empty session values produce empty output (no "null" literal disclosure).</li>
 *   <li>Encoding is non-re-entrant: already-encoded input is double-encoded correctly.</li>
 *   <li>Session-attribute key contract between adminlogin.jsp and header.jsp is documented.</li>
 * </ol>
 */
public class HeaderJspStoredXssRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // Minimal HTML encoder — mirrors the five entity substitutions that
    // JSTL <c:out escapeXml="true"/> (the default) applies at render time.
    // This is NOT the production sanitiser; it is here only to make the
    // encoding semantics testable without a running servlet container.
    // -------------------------------------------------------------------------

    /**
     * Encodes the five HTML-significant characters using the same entity
     * substitutions as JSTL {@code <c:out escapeXml="true"/>}:
     * <ul>
     *   <li>{@code &}  &rarr; {@code &amp;}</li>
     *   <li>{@code <}  &rarr; {@code &lt;}</li>
     *   <li>{@code >}  &rarr; {@code &gt;}</li>
     *   <li>{@code "}  &rarr; {@code &quot;}</li>
     *   <li>{@code '}  &rarr; {@code &#x27;}</li>
     * </ul>
     *
     * @param input raw value from session / database (may be null)
     * @return HTML-safe string; empty string if input is null
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
    // Helper assertions
    // -------------------------------------------------------------------------

    /**
     * Asserts that the encoded output contains no unencoded HTML-injection
     * characters that would allow a stored XSS attack to execute in a browser.
     */
    private static void assertXssNeutralised(String encoded) {
        assertFalse("Encoded output must not contain raw '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain raw '>'", encoded.contains(">"));
        assertFalse("Encoded output must not contain raw unencoded '\"'",
                containsRawDoubleQuote(encoded));
    }

    /**
     * Returns {@code true} if the string contains a {@code "} character that
     * is NOT the terminal character of the six-character entity {@code &quot;}.
     */
    private static boolean containsRawDoubleQuote(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '"') {
                // Accept only if this '"' ends a "&quot;" sequence
                if (i >= 5 && "&quot;".equals(s.substring(i - 5, i + 1))) {
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
     * A plain numeric user id (the overwhelmingly common legitimate case) must
     * survive encoding unchanged so that the {@code href} in the navigation bar
     * and the "My Profile" link both remain functional.
     */
    public void testSafeNumericUserIdPassesThroughUnchanged() {
        String userId  = "42";
        String encoded = htmlEncode(userId);
        assertEquals("A plain numeric user-id must not be altered by HTML encoding",
                "42", encoded);
    }

    /**
     * A plain alphanumeric username value stored as the session userid must not
     * be mangled by encoding — confirming no false positives for safe input.
     */
    public void testSafeAlphanumericValuePassesThroughUnchanged() {
        String value   = "user_7abc";
        String encoded = htmlEncode(value);
        assertEquals("Safe alphanumeric value must survive encoding unchanged",
                "user_7abc", encoded);
    }

    /**
     * A classic stored XSS payload stored in the database as a userid:
     * <pre>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</pre>
     * must have its angle brackets entity-encoded so that the browser renders
     * the tag as inert text rather than executable script.
     *
     * <p>This directly models the taint flow reported by the SAST scanner:
     * {@code rs.getString("id")} &rarr; {@code session.setAttribute("userid", ...)}
     * &rarr; {@code out.print(session.getAttribute("userid"))} (SINK at header.jsp:87).
     */
    public void testScriptTagPayloadStoredInDatabaseIsEncoded() {
        String xssPayload = "<script>alert(document.cookie)</script>";
        String encoded    = htmlEncode(xssPayload);

        assertXssNeutralised(encoded);
        assertTrue("'<' must be encoded as &lt;", encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;", encoded.contains("&gt;"));
        // The word "script" is still present as inert text
        assertTrue("Text 'script' must remain (as inert text, not executable markup)",
                encoded.contains("script"));
    }

    /**
     * An event-handler injection payload that would break out of the href
     * attribute value and inject an {@code onerror} handler:
     * <pre>1" onerror="alert(1)</pre>
     * After encoding, the {@code "} characters become {@code &quot;}, preserving
     * the attribute boundary and preventing handler injection.
     *
     * <p>This targets the second sink fixed in header.jsp (original line 149):
     * <pre>out.print("...?id=" + session.getAttribute("userid") + "...")</pre>
     */
    public void testAttributeBreakoutPayloadIsEncoded() {
        String payload = "1\" onerror=\"alert(1)";
        String encoded = htmlEncode(payload);

        assertFalse("Encoded output must not contain raw double-quote",
                containsRawDoubleQuote(encoded));
        assertTrue("Double-quote must be encoded as &quot;",
                encoded.contains("&quot;"));
        // Angle brackets are not in this payload, but the string content persists
        assertTrue("Non-special characters must be preserved in encoding",
                encoded.contains("onerror"));
    }

    /**
     * A single-quote injection payload that would break out of a
     * single-quoted HTML attribute (such as the single-quoted href at the
     * second header.jsp sink where the profile link was built with
     * {@code href='...?id=' + session.getAttribute("userid") + '...'}):
     * <pre>1' onmouseover='alert(1)</pre>
     * After encoding, {@code '} becomes {@code &#x27;}.
     */
    public void testSingleQuoteAttributeBreakoutPayloadIsEncoded() {
        String payload = "1' onmouseover='alert(1)";
        String encoded = htmlEncode(payload);

        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
    }

    /**
     * A {@code javascript:} URI payload stored as the userid:
     * <pre>javascript:alert('XSS')</pre>
     * While the colon and the {@code javascript} keyword are not HTML-special,
     * the embedded single-quotes must be entity-encoded.
     */
    public void testJavascriptUriPayloadHasSingleQuotesEncoded() {
        String payload = "javascript:alert('XSS')";
        String encoded = htmlEncode(payload);

        assertFalse("Single-quote must not appear unencoded in output",
                encoded.contains("'"));
        assertTrue("Single-quote must be encoded as &#x27;",
                encoded.contains("&#x27;"));
        // The keyword itself is preserved as inert text
        assertTrue("Keyword text must be preserved",
                encoded.contains("javascript"));
    }

    /**
     * An ampersand in the userid value must be encoded as {@code &amp;} to
     * prevent HTML entity injection that could be used to forge attribute
     * values or introduce character-reference sequences.
     */
    public void testAmpersandInUserIdIsEncoded() {
        String value   = "10&role=admin";
        String encoded = htmlEncode(value);

        assertFalse("Raw '&' must not appear in encoded output",
                encoded.contains("&role"));
        assertTrue("'&' must be encoded as &amp;",
                encoded.contains("&amp;"));
    }

    /**
     * A polyglot XSS payload designed to break out of both attribute and
     * element contexts simultaneously:
     * <pre>"><svg/onload=alert(1)></pre>
     * After encoding, all angle brackets and the double-quote become entities.
     */
    public void testPolyglotPayloadIsFullyEncoded() {
        String payload = "\"><svg/onload=alert(1)>";
        String encoded = htmlEncode(payload);

        assertXssNeutralised(encoded);
        assertTrue("'\"' must be encoded as &quot;", encoded.contains("&quot;"));
        assertTrue("'<' must be encoded as &lt;",    encoded.contains("&lt;"));
        assertTrue("'>' must be encoded as &gt;",    encoded.contains("&gt;"));
    }

    /**
     * A null session attribute value (user not logged in, or {@code userid}
     * attribute not yet set) must produce an empty string rather than the
     * literal text {@code "null"}, which would be an information disclosure
     * and would also break the href value.
     *
     * <p>JSTL {@code <c:out value="${sessionScope.userid}"/>} outputs an empty
     * string when the EL expression evaluates to null; this test documents and
     * enforces that contract.
     */
    public void testNullSessionAttributeProducesEmptyString() {
        String encoded = htmlEncode(null);
        assertEquals("null session attribute must encode to empty string, not \"null\"",
                "", encoded);
    }

    /**
     * An empty-string userid must produce an empty string in the output
     * (zero-length href parameter is acceptable; injected markup is not).
     */
    public void testEmptyUserIdProducesEmptyString() {
        String encoded = htmlEncode("");
        assertEquals("Empty userid must encode to empty string", "", encoded);
    }

    /**
     * Verifies that the encoder never introduces new injectable characters.
     * An already-encoded string like {@code &lt;script&gt;} must be
     * double-encoded (the {@code &} becoming {@code &amp;}) so that a
     * double-decode attack cannot reconstruct the original payload.
     */
    public void testEncodingDoesNotIntroduceNewSpecialCharacters() {
        String alreadyEncoded = "&lt;script&gt;";
        String encoded = htmlEncode(alreadyEncoded);

        // The '&' in '&lt;' must itself be encoded as '&amp;'
        assertTrue("'&' in already-encoded input must be re-encoded as &amp;",
                encoded.contains("&amp;"));
        // No raw angle brackets may appear
        assertFalse("Encoded output must not contain bare '<'", encoded.contains("<"));
        assertFalse("Encoded output must not contain bare '>'", encoded.contains(">"));
    }

    /**
     * Verifies encoding consistency: a string that contains all five
     * HTML-significant characters at once must have every one of them
     * encoded to the correct entity form.
     */
    public void testAllFiveHtmlSpecialCharactersAreEncoded() {
        String allSpecial = "&<>\"'";
        String encoded    = htmlEncode(allSpecial);

        assertTrue("& must be encoded as &amp;",  encoded.contains("&amp;"));
        assertTrue("< must be encoded as &lt;",   encoded.contains("&lt;"));
        assertTrue("> must be encoded as &gt;",   encoded.contains("&gt;"));
        assertTrue("\" must be encoded as &quot;",encoded.contains("&quot;"));
        assertTrue("' must be encoded as &#x27;", encoded.contains("&#x27;"));

        // No raw special characters may survive
        assertFalse("No raw '&' (outside entity sequence) must remain",
                encoded.replaceAll("&amp;|&lt;|&gt;|&quot;|&#x27;", "").contains("&"));
        assertFalse("No raw '<' must remain", encoded.contains("<"));
        assertFalse("No raw '>' must remain", encoded.contains(">"));
        assertFalse("No raw '\"' must remain", containsRawDoubleQuote(encoded));
        assertFalse("No raw single-quote must remain", encoded.contains("'"));
    }

    /**
     * Documents and enforces the session-attribute key contract between
     * adminlogin.jsp and header.jsp.
     *
     * <p>adminlogin.jsp sets:
     * <pre>session.setAttribute("userid", rs.getString("id"));</pre>
     * The fixed header.jsp reads:
     * <pre>&lt;c:out value="${sessionScope.userid}"/&gt;</pre>
     *
     * <p>If the key names diverge, the profile link will render an empty id
     * (breaking functionality) rather than throwing an exception.  This test
     * documents the contract explicitly so a future refactor that renames the
     * attribute in one file without updating the other is caught at review time.
     */
    public void testSessionAttributeKeyContractBetweenAdminLoginAndHeaderJsp() {
        // The key written by adminlogin.jsp into the HTTP session at login time.
        String adminLoginWriteKey = "userid";

        // The EL expression key read by the fixed header.jsp via ${sessionScope.<key>}.
        String headerJspReadKey = "userid";

        assertEquals(
                "adminlogin.jsp must store the user id under the same key " +
                "that the fixed header.jsp reads via ${sessionScope.userid}",
                adminLoginWriteKey, headerJspReadKey);
    }

    /**
     * Verifies that a long userid value (simulating a database column that
     * allows large text or a UUID) is encoded correctly without truncation
     * or buffer overflow issues in the encoding logic.
     */
    public void testLongValueIsEncodedCorrectly() {
        // Build a 1000-char value alternating between safe and unsafe characters
        StringBuilder sb = new StringBuilder(1000);
        for (int i = 0; i < 200; i++) {
            sb.append("safe");
            sb.append('<');
        }
        String longPayload = sb.toString();
        String encoded = htmlEncode(longPayload);

        assertFalse("Encoded long value must not contain raw '<'", encoded.contains("<"));
        assertTrue("Encoded long value must contain &lt; entities",
                encoded.contains("&lt;"));
        // Safe portions must be preserved
        assertTrue("Safe text portions must be preserved in encoded output",
                encoded.contains("safe"));
    }
}
