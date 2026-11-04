package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the SQL injection in Register.java where the username
 * was concatenated into the INSERT INTO UserMessages statement. The servlet
 * needs a container and database, so the source is inspected to make sure the
 * statement is parameterized.
 */
public class RegisterServletTest extends TestCase {

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

    public void testUserMessagesInsertIsParameterized() {
        assertTrue(source.contains(
                "prepareStatement(\"INSERT into UserMessages(recipient, sender, subject, msg) values (?,'admin',"));
        assertTrue(source.contains("msgStmt.setString(1, user)"));
        assertTrue(source.contains("msgStmt.executeUpdate()"));
    }

    public void testUserMessagesInsertHasNoConcatenatedUsername() {
        assertFalse(source.contains("UserMessages(recipient, sender, subject, msg) values ('\"+user"));
        assertFalse(source.contains("stmt.executeUpdate(\"INSERT into UserMessages"));
    }
}
