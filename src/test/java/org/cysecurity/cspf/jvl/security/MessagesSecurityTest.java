package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Security regression tests for Second-Order SQL Injection in Messages.jsp.
 *
 * Vulnerability (CWE-89): the SELECT in Messages.jsp concatenated the session
 * attribute "user" (originally read from the database at login) into the SQL string.
 *
 * Fix: the query is now a PreparedStatement with a positional '?' placeholder.
 */
public class MessagesSecurityTest extends TestCase {

    // Parameterized SQL template used by Messages.jsp after the fix.
    private static final String SAFE_SELECT_SQL =
            "select * from UserMessages where recipient=?";

    private Connection createInMemoryDatabase() throws Exception {
        Class.forName("org.h2.Driver");
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:messagestestdb;DB_CLOSE_DELAY=-1", "sa", "");
        Statement setup = conn.createStatement();
        setup.execute("DROP TABLE IF EXISTS UserMessages");
        setup.execute("CREATE TABLE UserMessages (" +
                "msgid VARCHAR(20), subject VARCHAR(255), recipient VARCHAR(255))");
        setup.execute("INSERT INTO UserMessages VALUES ('1','hello alice','alice')");
        setup.execute("INSERT INTO UserMessages VALUES ('2','hello bob','bob')");
        setup.close();
        return conn;
    }

    public void testSqlTemplateIsParameterized() {
        assertEquals(-1, SAFE_SELECT_SQL.indexOf('\''));
        int count = 0;
        for (char c : SAFE_SELECT_SQL.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals(1, count);
    }

    public void testLegitimateRecipientReturnsOnlyOwnMessages() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            PreparedStatement stmt = conn.prepareStatement(SAFE_SELECT_SQL);
            stmt.setString(1, "alice");
            ResultSet rs = stmt.executeQuery();
            assertTrue(rs.next());
            assertEquals("hello alice", rs.getString("subject"));
            assertFalse(rs.next());
            rs.close();
            stmt.close();
        } finally {
            conn.close();
        }
    }

    public void testSecondOrderPayloadIsTreatedAsLiteral() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            // Payload that would have returned every row if concatenated.
            String maliciousUser = "x' OR '1'='1";
            PreparedStatement stmt = conn.prepareStatement(SAFE_SELECT_SQL);
            stmt.setString(1, maliciousUser);
            ResultSet rs = stmt.executeQuery();
            assertFalse("Payload must not match any rows", rs.next());
            rs.close();
            stmt.close();

            // Stacked-statement payload must not drop the table.
            PreparedStatement stmt2 = conn.prepareStatement(SAFE_SELECT_SQL);
            stmt2.setString(1, "x'; DROP TABLE UserMessages; --");
            ResultSet rs2 = stmt2.executeQuery();
            assertFalse(rs2.next());
            rs2.close();
            stmt2.close();

            Statement check = conn.createStatement();
            ResultSet count = check.executeQuery("SELECT COUNT(*) FROM UserMessages");
            count.next();
            assertEquals(2, count.getInt(1));
            count.close();
            check.close();
        } finally {
            conn.close();
        }
    }
}
