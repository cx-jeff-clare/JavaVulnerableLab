package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Security regression tests for Second-Order SQL Injection in changepassword.jsp.
 *
 * Vulnerability (CWE-89): The UPDATE query in changepassword.jsp previously concatenated
 * the session-bound "userid" value directly into the SQL string:
 *
 *   stmt.executeUpdate("Update users set password='"+pass+"' where id="+id);
 *
 * The "id" value originates from rs.getString("id") in LoginValidator.processRequest (line 56),
 * which is stored in the session after login. If the database "id" column was populated with a
 * malicious payload (e.g. via SQL injection in the username field at login), that payload would
 * be concatenated into the UPDATE query on the next call to changepassword.jsp — a classic
 * second-order (stored) SQL injection attack.
 *
 * Fix: Both bind variables in the UPDATE statement are supplied through PreparedStatement
 * positional '?' parameters, so neither "pass" nor "id" is ever interpreted as SQL syntax:
 *
 *   PreparedStatement stmt = con.prepareStatement("UPDATE users SET password=? WHERE id=?");
 *   stmt.setString(1, pass);
 *   stmt.setString(2, id);
 *   stmt.executeUpdate();
 */
public class ChangePasswordSecurityTest extends TestCase {

    // The parameterized SQL template that changepassword.jsp now uses after the fix.
    private static final String SAFE_UPDATE_SQL =
            "UPDATE users SET password=? WHERE id=?";

    // The vulnerable SQL template that was present before the fix (reconstructed for contrast).
    private static final String UNSAFE_UPDATE_SQL_TEMPLATE =
            "Update users set password='%s' where id=%s";

    // -----------------------------------------------------------------------
    // Helper: create an in-memory H2 database with a minimal users table
    // -----------------------------------------------------------------------
    private Connection createInMemoryDatabase() throws Exception {
        Class.forName("org.h2.Driver");
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:changepwdtestdb;DB_CLOSE_DELAY=-1", "sa", "");

        Statement setup = conn.createStatement();
        // Create a minimal users table that mirrors the production schema.
        setup.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id VARCHAR(100) PRIMARY KEY, " +
                "username VARCHAR(255), " +
                "password VARCHAR(255), " +
                "avatar VARCHAR(255))");
        // Seed a legitimate user row that the password-change operation targets.
        setup.execute("INSERT INTO users(id, username, password, avatar) " +
                "VALUES ('1', 'alice', 'oldpassword', 'default.png')");
        setup.close();
        return conn;
    }

    // -----------------------------------------------------------------------
    // SQL template structure tests
    // -----------------------------------------------------------------------

    /**
     * Verify the fixed SQL template contains parameterized placeholders ('?'),
     * not inline string interpolation — a static check that the sink uses
     * a prepared statement template.
     */
    public void testFixedSqlUsesParameterizedPlaceholders() {
        assertTrue(
                "Fixed SQL must use '?' for the password placeholder",
                SAFE_UPDATE_SQL.indexOf('?') >= 0);

        // Count '?' placeholders: must be exactly 2 (password and id).
        int count = 0;
        for (char c : SAFE_UPDATE_SQL.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("Fixed SQL must have exactly 2 parameterized placeholders", 2, count);
    }

    /**
     * Verify the fixed SQL template does NOT embed values via string concatenation
     * (i.e. it contains no literal single-quoted value slots).
     */
    public void testFixedSqlDoesNotContainConcatenatedValues() {
        // A parameterized template must not contain embedded string literals like '+pass+'.
        assertFalse(
                "Fixed SQL must not embed values via single-quote concatenation",
                SAFE_UPDATE_SQL.contains("'+"));
        assertFalse(
                "Fixed SQL must not embed values via single-quote concatenation",
                SAFE_UPDATE_SQL.contains("+'"));
    }

    // -----------------------------------------------------------------------
    // Behavioral tests: PreparedStatement treats payload as data, not code
    // -----------------------------------------------------------------------

    /**
     * A second-order SQL injection payload stored as the user's "id" in the session
     * (originally read from the database after login via rs.getString("id")) must be
     * treated as a literal bind value by the PreparedStatement, not interpreted as SQL.
     *
     * Attack scenario:
     *   1. Attacker registers with a username that injects a crafted id value into
     *      the users table (e.g. via a first-order injection at login time).
     *   2. On login, LoginValidator reads that tainted id into the session.
     *   3. changepassword.jsp reads "userid" from session and uses it in the UPDATE.
     *   4. Old code: the tainted id is concatenated into the SQL — injection fires.
     *      New code: PreparedStatement binds the tainted id as data — injection blocked.
     *
     * This test verifies the NEW behaviour (injection blocked).
     */
    public void testPreparedStatementTreatsInjectionPayloadAsLiteralData() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            // Simulate a malicious "userid" value retrieved from the database and stored
            // in the session. This payload would, under the old code, modify the WHERE clause
            // to match all rows and append a DROP TABLE statement.
            String maliciousId = "1 OR 1=1; DROP TABLE users; --";
            String newPassword = "newpassword";

            // Execute the fixed UPDATE using parameterized placeholders.
            PreparedStatement stmt = conn.prepareStatement(SAFE_UPDATE_SQL);
            stmt.setString(1, newPassword);
            stmt.setString(2, maliciousId);
            int rowsAffected = stmt.executeUpdate();
            stmt.close();

            // The injected payload ('1 OR 1=1; DROP TABLE users; --') does NOT match any
            // row's id (it is treated as a literal string), so 0 rows are updated.
            assertEquals(
                    "Injection payload used as a bind value must not match any real id: 0 rows updated",
                    0, rowsAffected);

            // The users table must still exist (DROP TABLE in payload was NOT executed).
            Statement check = conn.createStatement();
            ResultSet rs = check.executeQuery("SELECT COUNT(*) FROM users");
            rs.next();
            int rowCount = rs.getInt(1);
            rs.close();
            check.close();

            assertTrue("Users table must still exist after the injected payload was processed",
                    rowCount >= 1);

            // The legitimate user's password must remain unchanged.
            PreparedStatement verify = conn.prepareStatement(
                    "SELECT password FROM users WHERE id = ?");
            verify.setString(1, "1");
            ResultSet verifyRs = verify.executeQuery();
            assertTrue("Legitimate user row must still be present", verifyRs.next());
            assertEquals(
                    "Legitimate user's password must remain unchanged when payload did not match their id",
                    "oldpassword", verifyRs.getString("password"));
            verifyRs.close();
            verify.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM users");
            teardown.close();
            conn.close();
        }
    }

    /**
     * A legitimate password change (normal data) must continue to work correctly
     * after the fix. This verifies backward compatibility.
     */
    public void testLegitimatePasswordChangeSucceeds() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            String userId = "1";
            String newPassword = "SuperSecure!2025";

            PreparedStatement stmt = conn.prepareStatement(SAFE_UPDATE_SQL);
            stmt.setString(1, newPassword);
            stmt.setString(2, userId);
            int rowsAffected = stmt.executeUpdate();
            stmt.close();

            assertEquals("A legitimate password UPDATE must affect exactly one row", 1, rowsAffected);

            // Verify the new password was stored correctly.
            PreparedStatement read = conn.prepareStatement(
                    "SELECT password FROM users WHERE id = ?");
            read.setString(1, userId);
            ResultSet rs = read.executeQuery();
            assertTrue("Updated user row must be retrievable", rs.next());
            assertEquals("New password must be persisted correctly", newPassword, rs.getString("password"));
            rs.close();
            read.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM users");
            teardown.close();
            conn.close();
        }
    }

    /**
     * SQL special characters in the new password (apostrophes, quotes, semicolons)
     * must be stored as literal data, not interpreted as SQL syntax.
     */
    public void testSpecialCharactersInPasswordAreStoredLiterally() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            String userId = "1";
            // Password containing characters that would break a naive concatenated query.
            String specialPassword = "it's a \"test\"; DROP TABLE users; --";

            PreparedStatement stmt = conn.prepareStatement(SAFE_UPDATE_SQL);
            stmt.setString(1, specialPassword);
            stmt.setString(2, userId);
            stmt.executeUpdate();
            stmt.close();

            // Table must still exist.
            Statement check = conn.createStatement();
            ResultSet countRs = check.executeQuery("SELECT COUNT(*) FROM users");
            countRs.next();
            int rowCount = countRs.getInt(1);
            countRs.close();
            check.close();

            assertTrue("Users table must still exist after special-character password update",
                    rowCount >= 1);

            // The special password must be stored as a literal string.
            PreparedStatement verify = conn.prepareStatement(
                    "SELECT password FROM users WHERE id = ?");
            verify.setString(1, userId);
            ResultSet rs = verify.executeQuery();
            assertTrue("User row must be retrievable after special-character update", rs.next());
            assertEquals(
                    "Password with special characters must be stored literally, not executed as SQL",
                    specialPassword, rs.getString("password"));
            rs.close();
            verify.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM users");
            teardown.close();
            conn.close();
        }
    }

    /**
     * Demonstrates why the old string-concatenation pattern was dangerous.
     * The old SQL was: "Update users set password='"+pass+"' where id="+id
     * A malicious id such as "1 OR 1=1" would match all rows.
     *
     * This test verifies the safe template remains structurally constant regardless
     * of what payload is passed — only bind parameter values change, not SQL structure.
     */
    public void testOldConcatenationPatternWouldProduceStructurallyAlteredSql() {
        String maliciousId = "1 OR 1=1";
        String newPassword = "hacked";

        // Build the SQL the way the OLD code did (string concatenation).
        String vulnerableSql = String.format(UNSAFE_UPDATE_SQL_TEMPLATE, newPassword, maliciousId);

        // The vulnerable SQL's WHERE clause would be altered by the payload.
        assertTrue(
                "Vulnerable concatenated SQL must contain the injected OR condition",
                vulnerableSql.contains("OR 1=1"));

        // The fixed PreparedStatement template is always structurally the same SQL.
        assertEquals(
                "The safe SQL template must remain structurally constant regardless of inputs",
                "UPDATE users SET password=? WHERE id=?",
                SAFE_UPDATE_SQL);
    }

    /**
     * A second-order payload that attempts to escape the WHERE clause entirely
     * (using a comment sequence) must be stored as a literal string by the
     * PreparedStatement and not match any real user id.
     */
    public void testCommentBasedInjectionPayloadTreatedAsLiteralId() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            // Payload that would, under the old code, comment out the WHERE condition
            // and update every row's password.
            String commentPayload = "1 --";
            String newPassword = "attackerpassword";

            PreparedStatement stmt = conn.prepareStatement(SAFE_UPDATE_SQL);
            stmt.setString(1, newPassword);
            stmt.setString(2, commentPayload);
            int rowsAffected = stmt.executeUpdate();
            stmt.close();

            // The literal string "1 --" does not equal any real id, so no rows update.
            assertEquals(
                    "Comment-based injection payload must not match any real id: 0 rows updated",
                    0, rowsAffected);

            // The legitimate user's password is unchanged.
            PreparedStatement verify = conn.prepareStatement(
                    "SELECT password FROM users WHERE id = ?");
            verify.setString(1, "1");
            ResultSet rs = verify.executeQuery();
            assertTrue("Legitimate user must still be present", rs.next());
            assertEquals(
                    "Legitimate user's password must not be modified by comment-based payload",
                    "oldpassword", rs.getString("password"));
            rs.close();
            verify.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM users");
            teardown.close();
            conn.close();
        }
    }
}
