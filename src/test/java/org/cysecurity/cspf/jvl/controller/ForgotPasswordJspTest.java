package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the SQL injection in ForgotPassword.jsp.
 * No JSP engine is available to the unit tests, so the JSP source is inspected
 * to make sure the SELECT statement is parameterized and no request data is
 * concatenated into the SQL text.
 */
public class ForgotPasswordJspTest extends TestCase {

    private static final String JSP_PATH =
            "src/main/webapp/ForgotPassword.jsp";

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

    public void testSelectUsesPreparedStatementWithPlaceholders() {
        assertTrue(source.contains(
                "prepareStatement(\"select * from users where username=? and secret=?\")"));
        assertTrue(source.contains("stmt.setString(1, request.getParameter(\"username\").trim())"));
        assertTrue(source.contains("stmt.setString(2, request.getParameter(\"secret\"))"));
        assertTrue(source.contains("stmt.executeQuery()"));
    }

    public void testNoRawStatementOrConcatenatedSql() {
        assertFalse(source.contains("createStatement()"));
        assertFalse(source.contains("username='\""));
        assertFalse(source.contains("secret='\""));
        assertFalse(source.contains("executeQuery(\""));
    }
}
