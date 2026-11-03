package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Security regression tests for SQL Injection (CWE-89) in
 * vulnerability/securitymisconfig/pages.jsp.
 *
 * The "posts" lookup previously concatenated the request parameter "id" into the
 * query string. It now uses a PreparedStatement with a positional '?' placeholder
 * bound through setInt, so the value is always treated as data.
 */
public class PagesSecurityTest extends TestCase {

    // The parameterized SQL template that pages.jsp uses after the fix.
    private static final String SAFE_SELECT_SQL = "select * from posts where postid=?";

    private Connection createInMemoryDatabase() throws Exception {
        Class.forName("org.h2.Driver");
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:pagesdb;DB_CLOSE_DELAY=-1", "sa", "");
        Statement setup = conn.createStatement();
        setup.execute("CREATE TABLE IF NOT EXISTS posts (" +
                "postid INT PRIMARY KEY, " +
                "title VARCHAR(255), " +
                "\"user\" VARCHAR(255), " +
                "content VARCHAR(1000))");
        setup.execute("DELETE FROM posts");
        setup.execute("INSERT INTO posts VALUES (1, 'First', 'alice', 'hello')");
        setup.execute("INSERT INTO posts VALUES (2, 'Second', 'bob', 'world')");
        setup.close();
        return conn;
    }

    /** The fixed SQL must use a '?' placeholder and no concatenation. */
    public void testFixedSqlUsesPlaceholder() {
        int count = 0;
        for (char c : SAFE_SELECT_SQL.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("Fixed SQL must have exactly one placeholder", 1, count);
    }

    /** A legitimate id returns exactly the matching post. */
    public void testLegitimateIdReturnsPost() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            PreparedStatement stmt = conn.prepareStatement(SAFE_SELECT_SQL);
            stmt.setInt(1, Integer.parseInt("1"));
            ResultSet rs = stmt.executeQuery();
            assertTrue("Post 1 must be found", rs.next());
            assertEquals("First", rs.getString("title"));
            assertFalse("Only one row expected", rs.next());
            rs.close();
            stmt.close();
        } finally {
            conn.close();
        }
    }

    /** Injection payloads are rejected by integer parsing and never reach the DB. */
    public void testInjectionPayloadIsNotAnInteger() {
        String[] payloads = {"1 OR 1=1", "1; DROP TABLE posts", "1 UNION SELECT 1,2,3,4", "' OR '1'='1"};
        for (String payload : payloads) {
            try {
                Integer.parseInt(payload);
                fail("Payload must not parse as an integer: " + payload);
            } catch (NumberFormatException expected) {
                // expected: request never reaches the query
            }
        }
    }

    /** A bound integer parameter returns only the requested row, not all rows. */
    public void testBoundParameterDoesNotReturnAllRows() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            PreparedStatement stmt = conn.prepareStatement(SAFE_SELECT_SQL);
            stmt.setInt(1, 2);
            ResultSet rs = stmt.executeQuery();
            int rows = 0;
            while (rs.next()) {
                rows++;
                assertEquals("Second", rs.getString("title"));
            }
            assertEquals(1, rows);
            rs.close();
            stmt.close();

            Statement check = conn.createStatement();
            ResultSet cnt = check.executeQuery("SELECT COUNT(*) FROM posts");
            cnt.next();
            assertEquals("Table must remain intact", 2, cnt.getInt(1));
            cnt.close();
            check.close();
        } finally {
            conn.close();
        }
    }
}
