package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the SQL injection in Register.processRequest (the
 * "About" parameter and the other registration fields). The servlet needs a
 * live container and database, so the source is inspected to make sure the
 * users INSERT is parameterized and no request data is concatenated into SQL.
 */
public class RegisterSqlInjectionTest extends TestCase {

    private static final String SRC_PATH =
            "src/main/java/org/cysecurity/cspf/jvl/controller/Register.java";

    private String source;

    protected void setUp() throws Exception {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new FileReader(new File(SRC_PATH)));
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

    public void testUserInsertUsesPreparedStatementWithPlaceholders() {
        assertTrue(source.contains(
                "prepareStatement(\"INSERT into users(username, password, email, About,avatar,privilege,secretquestion,secret) "
                + "values (?,?,?,?,'default.jpg','user',1,?)\")"));
        assertTrue(source.contains("stmt.setString(1, user)"));
        assertTrue(source.contains("stmt.setString(2, pass)"));
        assertTrue(source.contains("stmt.setString(3, email)"));
        assertTrue(source.contains("stmt.setString(4, about)"));
        assertTrue(source.contains("stmt.setString(5, secret)"));
        assertTrue(source.contains("stmt.executeUpdate()"));
    }

    public void testNoRawStatementOrConcatenatedSql() {
        assertFalse(source.contains("createStatement()"));
        assertFalse(source.contains("'\"+about+\"'"));
        assertFalse(source.contains("'\"+user+\"'"));
        assertFalse(source.contains("'\"+pass+\"'"));
        assertFalse(source.contains("'\"+email+\"'"));
        assertFalse(source.contains("'\"+secret+\"'"));
        assertFalse(source.contains("executeUpdate(\""));
    }
}
