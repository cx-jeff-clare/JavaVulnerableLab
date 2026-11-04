package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the second-order SQL injection in
 * vulnerability/csrf/changepassword.jsp. No JSP engine is available to the
 * unit tests, so the JSP source is inspected to make sure the UPDATE statement
 * is parameterized and neither the password nor the session user id is
 * concatenated into the SQL text.
 */
public class ChangePasswordJspTest extends TestCase {

    private static final String JSP_PATH =
            "src/main/webapp/vulnerability/csrf/changepassword.jsp";

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

    public void testUpdateUsesPreparedStatementWithPlaceholders() {
        assertTrue(source.contains(
                "prepareStatement(\"Update users set password=? where id=?\")"));
        assertTrue(source.contains("stmt.setString(1, pass)"));
        assertTrue(source.contains("stmt.setString(2, id)"));
        assertTrue(source.contains("stmt.executeUpdate()"));
    }

    public void testNoRawStatementOrConcatenatedSql() {
        assertFalse(source.contains("createStatement()"));
        assertFalse(source.contains("password='\"+pass"));
        assertFalse(source.contains("where id=\"+id"));
        assertFalse(source.contains("executeUpdate(\""));
    }
}
