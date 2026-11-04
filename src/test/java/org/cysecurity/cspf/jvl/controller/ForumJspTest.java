package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the SQL injection in vulnerability/forum.jsp.
 * No JSP engine is available to the unit tests, so the JSP source is inspected
 * to make sure the INSERT statement is parameterized and no request data is
 * concatenated into the SQL text.
 */
public class ForumJspTest extends TestCase {

    private static final String JSP_PATH =
            "src/main/webapp/vulnerability/forum.jsp";

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

    public void testInsertUsesPreparedStatementWithPlaceholders() {
        assertTrue(source.contains(
                "prepareStatement(\"INSERT into posts(content,title,user) values (?,?,?)\")"));
        assertTrue(source.contains("stmt.setString(1, content)"));
        assertTrue(source.contains("stmt.setString(2, title)"));
        assertTrue(source.contains("stmt.setString(3, user)"));
        assertTrue(source.contains("stmt.executeUpdate()"));
    }

    public void testNoConcatenatedInsertSql() {
        assertFalse(source.contains("executeUpdate(\""));
        assertFalse(source.contains("values ('\"+content"));
        assertFalse(source.contains("'\"+title+\"'"));
        assertFalse(source.contains("'\"+user+\"'"));
    }
}
