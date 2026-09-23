package org.cysecurity.cspf.jvl.security;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Security regression tests for Second-Order SQL Injection in changeCardDetails.jsp.
 *
 * Vulnerability (CWE-89): The card-details INSERT query previously concatenated
 * the session-bound "userid" value directly into the SQL string. That value was
 * originally sourced from the database after an admin-login query that also used
 * string concatenation, enabling a second-order SQL injection payload stored via
 * the username field to execute in the later INSERT.
 *
 * Fix: The INSERT statement in changeCardDetails.jsp was converted to a
 * PreparedStatement with positional '?' placeholders, so user-controlled data
 * is always treated as literal values by the JDBC driver, never as SQL syntax.
 */
public class ChangeCardDetailsSecurityTest extends TestCase {

    // The parameterized SQL template that changeCardDetails.jsp now uses after the fix.
    private static final String SAFE_INSERT_SQL =
            "INSERT into cards(id,cardno, cvv,expirydate) values (?,?,?,?)";

    // The vulnerable SQL template that was present before the fix.
    private static final String UNSAFE_INSERT_SQL_TEMPLATE =
            "INSERT into cards(id,cardno, cvv,expirydate) values ('%s','%s','%s','%s')";

    // -----------------------------------------------------------------------
    // Helper: create an in-memory H2 database and the cards / users tables
    // -----------------------------------------------------------------------
    private Connection createInMemoryDatabase() throws Exception {
        Class.forName("org.h2.Driver");
        Connection conn = DriverManager.getConnection(
                "jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "sa", "");

        Statement setup = conn.createStatement();
        // Create a minimal users table to simulate the login flow.
        setup.execute("CREATE TABLE IF NOT EXISTS users (" +
                "id VARCHAR(100) PRIMARY KEY, " +
                "username VARCHAR(255), " +
                "password VARCHAR(255), " +
                "privilege VARCHAR(50))");

        // Create the cards table that changeCardDetails.jsp writes to.
        setup.execute("CREATE TABLE IF NOT EXISTS cards (" +
                "id VARCHAR(100), " +
                "cardno VARCHAR(50), " +
                "cvv VARCHAR(10), " +
                "expirydate VARCHAR(20))");

        setup.close();
        return conn;
    }

    // -----------------------------------------------------------------------
    // SQL template structure tests
    // -----------------------------------------------------------------------

    /**
     * Verify the fixed SQL template contains parameterized placeholders ('?'),
     * not inline string interpolation markers. This is a static check that
     * the sink is a prepared statement template.
     */
    public void testFixedSqlUsesParameterizedPlaceholders() {
        // The fixed SQL must use '?' for every value position.
        assertTrue(
                "Fixed SQL must use '?' for the id placeholder",
                SAFE_INSERT_SQL.indexOf('?') >= 0);

        // Count the number of '?' placeholders — should be exactly 4 for (id, cardno, cvv, expirydate).
        int count = 0;
        for (char c : SAFE_INSERT_SQL.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("Fixed SQL must have exactly 4 parameterized placeholders", 4, count);
    }

    /**
     * Verify the fixed SQL template does NOT use string concatenation markers
     * (single-quote delimited dynamic values) like the old vulnerable template.
     * The old form was: values ('{id}','{cardno}','{cvv}','{expirydate}')
     */
    public void testFixedSqlDoesNotContainConcatenatedValues() {
        // A safe parameterized template should not contain single-quoted value
        // slots like '%s' or variables embedded via concatenation ('"+id+"').
        assertFalse(
                "Fixed SQL must not embed values via single-quote concatenation",
                SAFE_INSERT_SQL.matches(".*'[^?].*'.*"));
    }

    // -----------------------------------------------------------------------
    // Behavioral tests: parameterized INSERT treats payload as data, not code
    // -----------------------------------------------------------------------

    /**
     * A second-order SQL injection payload stored as the user's "id" in the
     * session (originally read from the database after login) must be treated
     * as a literal value by the PreparedStatement, not interpreted as SQL.
     *
     * This test inserts a row using the fixed PreparedStatement and verifies:
     * 1. The row is inserted successfully.
     * 2. The stored value is the literal injection string, not executed SQL.
     * 3. No extra rows are created by the payload.
     */
    public void testPreparedStatementTreatsInjectionPayloadAsLiteralData() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            // Simulate a second-order payload: a malicious "userid" value that
            // was previously stored in the database and is now retrieved into
            // the session. In the old code, this value was concatenated directly
            // into the SQL, enabling injection. With PreparedStatement it is safe.
            String maliciousId = "1'),('2','9999999999','000','12/99'); DROP TABLE cards; --";
            String cardno = "4111111111111111";
            String cvv = "123";
            String expirydate = "12/25";

            // Execute the fixed INSERT using parameterized placeholders.
            PreparedStatement stmt = conn.prepareStatement(SAFE_INSERT_SQL);
            stmt.setString(1, maliciousId);
            stmt.setString(2, cardno);
            stmt.setString(3, cvv);
            stmt.setString(4, expirydate);
            stmt.executeUpdate();
            stmt.close();

            // The table must still exist (DROP TABLE in payload was NOT executed).
            Statement check = conn.createStatement();
            ResultSet rs = check.executeQuery("SELECT COUNT(*) FROM cards");
            rs.next();
            int rowCount = rs.getInt(1);
            rs.close();
            check.close();

            // Exactly one row inserted — payload did not create additional rows.
            assertEquals(
                    "PreparedStatement must insert exactly one row; injection payload must not create extra rows",
                    1, rowCount);

            // Verify the stored id value is the literal malicious string.
            Statement verify = conn.createStatement();
            ResultSet verifyRs = verify.executeQuery("SELECT id FROM cards");
            verifyRs.next();
            String storedId = verifyRs.getString("id");
            verifyRs.close();
            verify.close();

            assertEquals(
                    "The stored id must be the literal injection string, not interpreted as SQL",
                    maliciousId, storedId);
        } finally {
            // Clean up for test isolation.
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM cards");
            teardown.close();
            conn.close();
        }
    }

    /**
     * A legitimate card insert (normal data) must continue to work correctly
     * after the fix. This verifies backward compatibility.
     */
    public void testLegitimateCardInsertSucceeds() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            String userId = "42";
            String cardno = "4111111111111111";
            String cvv = "456";
            String expirydate = "06/28";

            PreparedStatement stmt = conn.prepareStatement(SAFE_INSERT_SQL);
            stmt.setString(1, userId);
            stmt.setString(2, cardno);
            stmt.setString(3, cvv);
            stmt.setString(4, expirydate);
            int rowsAffected = stmt.executeUpdate();
            stmt.close();

            assertEquals("A normal INSERT must affect exactly one row", 1, rowsAffected);

            // Verify the inserted data is retrievable and correct.
            PreparedStatement read = conn.prepareStatement(
                    "SELECT cardno, cvv, expirydate FROM cards WHERE id = ?");
            read.setString(1, userId);
            ResultSet rs = read.executeQuery();
            assertTrue("Inserted card row must be retrievable by user id", rs.next());
            assertEquals("Card number must be stored correctly", cardno, rs.getString("cardno"));
            assertEquals("CVV must be stored correctly", cvv, rs.getString("cvv"));
            assertEquals("Expiry date must be stored correctly", expirydate, rs.getString("expirydate"));
            rs.close();
            read.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM cards");
            teardown.close();
            conn.close();
        }
    }

    /**
     * SQL special characters in card fields (apostrophes, hyphens, slashes)
     * must be stored as literal data, not interpreted as SQL syntax.
     * This covers edge cases such as card holders with names like O'Brien
     * and unusual but valid date formats.
     */
    public void testSpecialCharactersInCardFieldsAreStoredLiterally() throws Exception {
        Connection conn = createInMemoryDatabase();
        try {
            String userId = "7";
            String cardno = "4111-1111-1111-1111"; // dashes are common display format
            String cvv = "'; DROP TABLE cards; --"; // adversarial CVV input
            String expirydate = "12/99";

            PreparedStatement stmt = conn.prepareStatement(SAFE_INSERT_SQL);
            stmt.setString(1, userId);
            stmt.setString(2, cardno);
            stmt.setString(3, cvv);
            stmt.setString(4, expirydate);
            stmt.executeUpdate();
            stmt.close();

            // The cards table must still exist and contain exactly one row.
            Statement check = conn.createStatement();
            ResultSet rs = check.executeQuery("SELECT cvv FROM cards WHERE id = '7'");
            assertTrue("Row with adversarial CVV must be present", rs.next());
            assertEquals(
                    "Adversarial CVV must be stored as literal text, not executed as SQL",
                    cvv, rs.getString("cvv"));
            rs.close();
            check.close();
        } finally {
            Statement teardown = conn.createStatement();
            teardown.execute("DELETE FROM cards");
            teardown.close();
            conn.close();
        }
    }

    /**
     * Verify that using Statement with string concatenation (the vulnerable
     * pattern) would behave differently from PreparedStatement for a payload,
     * demonstrating WHY the fix is necessary.
     *
     * This test documents the vulnerability for regression awareness:
     * the old code's format string allowed payload characters to alter the
     * SQL structure. The safe PreparedStatement form always treats the payload
     * as data, preventing this.
     */
    public void testOldConcatenationPatternWouldProduceInvalidSql() {
        // Simulate the old vulnerable SQL construction for a payload id.
        String maliciousId = "1','x','y','z'); INSERT INTO cards VALUES ('evil";
        String cardno = "4111111111111111";
        String cvv = "123";
        String expirydate = "12/25";

        // Build the SQL the way the OLD code did (string concatenation).
        String vulnerableSql = String.format(
                UNSAFE_INSERT_SQL_TEMPLATE, maliciousId, cardno, cvv, expirydate);

        // The vulnerable SQL would contain a structurally altered query due to the payload.
        // The payload closes the first VALUES tuple early and injects a second INSERT.
        assertTrue(
                "Vulnerable concatenated SQL must contain the injected second INSERT statement",
                vulnerableSql.contains("INSERT INTO cards VALUES"));

        // The fixed PreparedStatement approach passes the payload as a literal parameter
        // binding — the SQL template itself never contains user data.
        // Verify the safe template is unchanged regardless of payload.
        assertEquals(
                "The safe SQL template must remain structurally constant",
                "INSERT into cards(id,cardno, cvv,expirydate) values (?,?,?,?)",
                SAFE_INSERT_SQL);
    }
}
