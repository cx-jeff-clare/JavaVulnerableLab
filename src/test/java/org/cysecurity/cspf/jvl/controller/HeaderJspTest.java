package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the stored XSS in header.jsp, where the session "userid"
 * attribute (populated from the database at login) was printed unencoded. No
 * JSP engine is available to the unit tests, so the JSP source is inspected to
 * make sure the value is output through the JSTL HTML-escaping c:out tag.
 */
public class HeaderJspTest extends TestCase {

    private static final String JSP_PATH = "src/main/webapp/header.jsp";

    private String source;

    protected void setUp() throws Exception {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new FileReader(new File(JSP_PATH)));
        try {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } finally {
            r.close();
        }
        source = sb.toString();
    }

    public void testUserIdIsOutputWithCOut() {
        assertTrue(source.contains(
                "<%@ taglib uri=\"http://java.sun.com/jsp/jstl/core\" prefix=\"c\" %>"));
        assertTrue(source.contains(
                "myprofile.jsp?id=<c:out value=\"${sessionScope.userid}\"/>"));
    }

    public void testUserIdNotPrintedRaw() {
        assertFalse(source.contains("out.print(session.getAttribute(\"userid\"))"));
    }
}
