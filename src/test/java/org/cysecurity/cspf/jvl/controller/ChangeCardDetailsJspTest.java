package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the second-order SQL injection in changeCardDetails.jsp.
 * No JSP engine is available to the unit tests, so the JSP source is inspected
 * to make sure the INSERT statement is parameterized and no user/session data
 * is concatenated into the SQL text.
 */
public class ChangeCardDetailsJspTest extends TestCase {

    private static final String JSP_PATH =
            "src/main/webapp/changeCardDetails.jsp";

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
                "prepareStatement(\"INSERT into cards(id,cardno, cvv,expirydate) values (?,?,?,?)\")"));
        assertTrue(source.contains("stmt.setString(1, id)"));
        assertTrue(source.contains("stmt.setString(2, cardno)"));
        assertTrue(source.contains("stmt.setString(3, cvv)"));
        assertTrue(source.contains("stmt.setString(4, expirydate)"));
        assertTrue(source.contains("stmt.executeUpdate()"));
    }

    public void testNoRawStatementOrConcatenatedSql() {
        assertFalse(source.contains("createStatement()"));
        assertFalse(source.contains("values ('\"+id"));
        assertFalse(source.contains("'\"+cardno+\"'"));
        assertFalse(source.contains("executeUpdate(\""));
    }
}
