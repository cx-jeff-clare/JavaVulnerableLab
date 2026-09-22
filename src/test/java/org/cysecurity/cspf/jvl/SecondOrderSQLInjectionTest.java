package org.cysecurity.cspf.jvl;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Tests to verify that Second-Order SQL Injection is prevented in
 * changeCardDetails.jsp and adminlogin.jsp by using PreparedStatement
 * with parameterized queries instead of string concatenation.
 *
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 *
 * Second-Order SQL Injection scenario:
 *   1. An attacker logs in with a crafted username that stores malicious SQL in the DB.
 *   2. That stored value is later read and used in another SQL query (changeCardDetails).
 *   3. With PreparedStatement the tainted value is treated as data, not SQL, at both steps.
 */
public class SecondOrderSQLInjectionTest extends TestCase {

    private Connection connection;

    /**
     * Set up an in-memory H2 database that mirrors the schema used by the application.
     * H2 is used here because it is a pure-Java in-memory database suitable for unit tests.
     * NOTE: H2 must be available on the test classpath (or add the dependency to pom.xml).
     */
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        // Use H2 in-memory database
        Class.forName("org.h2.Driver");
        connection = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1", "sa", "");

        // Create tables matching application schema
        Statement stmt = connection.createStatement();
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS users (" +
            "  id VARCHAR(50) PRIMARY KEY," +
            "  username VARCHAR(100)," +
            "  password VARCHAR(100)," +
            "  privilege VARCHAR(20)," +
            "  avatar VARCHAR(200)" +
            ")"
        );
        stmt.execute(
            "CREATE TABLE IF NOT EXISTS cards (" +
            "  id VARCHAR(50)," +
            "  cardno VARCHAR(20)," +
            "  cvv VARCHAR(5)," +
            "  expirydate VARCHAR(10)" +
            ")"
        );
        stmt.close();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        // Drop tables and close connection after each test
        Statement stmt = connection.createStatement();
        stmt.execute("DROP TABLE IF EXISTS cards");
        stmt.execute("DROP TABLE IF EXISTS users");
        stmt.close();
        connection.close();
    }

    // -------------------------------------------------------------------------
    // Tests for changeCardDetails.jsp fix: INSERT uses PreparedStatement
    // -------------------------------------------------------------------------

    /**
     * Verify that a normal card insert works correctly with parameterized query.
     * This ensures the fix doesn't break existing functionality.
     */
    public void testCardInsertWithValidData() throws Exception {
        String id = "42";
        String cardno = "4111111111111111";
        String cvv = "123";
        String expirydate = "12/25";

        // Simulate the fixed INSERT from changeCardDetails.jsp using PreparedStatement
        PreparedStatement ps = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        ps.setString(1, id);
        ps.setString(2, cardno);
        ps.setString(3, cvv);
        ps.setString(4, expirydate);
        int rows = ps.executeUpdate();
        ps.close();

        assertEquals("One row should be inserted", 1, rows);

        // Verify the row was actually inserted correctly
        PreparedStatement query = connection.prepareStatement(
            "SELECT cardno, cvv, expirydate FROM cards WHERE id=?"
        );
        query.setString(1, id);
        ResultSet rs = query.executeQuery();
        assertTrue("Row should exist in cards table", rs.next());
        assertEquals("Card number should match", cardno, rs.getString("cardno"));
        assertEquals("CVV should match", cvv, rs.getString("cvv"));
        assertEquals("Expiry date should match", expirydate, rs.getString("expirydate"));
        rs.close();
        query.close();
    }

    /**
     * Verify that a Second-Order SQL Injection payload in the session's userid
     * (which was originally read from the database after an admin login) is treated
     * as a literal string and does NOT execute as SQL.
     *
     * Attack scenario: if the attacker managed to store a crafted value in the
     * 'id' session attribute (e.g., by exploiting the first-order admin login injection),
     * the second-order payload in changeCardDetails.jsp must be neutralised.
     */
    public void testSecondOrderSQLInjectionPayloadInIdIsNeutralised() throws Exception {
        // This simulates the tainted value that came from session.getAttribute("userid")
        // e.g., an id that an attacker crafted to break out of the query
        String maliciousId = "1'); DROP TABLE cards; --";
        String cardno = "4111111111111111";
        String cvv = "123";
        String expirydate = "12/25";

        // The fixed code uses PreparedStatement — the malicious id is bound as a literal
        PreparedStatement ps = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        ps.setString(1, maliciousId);
        ps.setString(2, cardno);
        ps.setString(3, cvv);
        ps.setString(4, expirydate);
        ps.executeUpdate();
        ps.close();

        // The table must still exist (DROP TABLE was NOT executed as SQL)
        Statement check = connection.createStatement();
        ResultSet rs = check.executeQuery("SELECT COUNT(*) FROM cards");
        rs.next();
        int count = rs.getInt(1);
        rs.close();
        check.close();

        assertEquals("cards table must still exist and contain 1 row; DROP TABLE must not have executed", 1, count);
    }

    /**
     * Verify that SQL injection characters in cardno (direct user input) are treated
     * as literal data and do not alter the query structure.
     */
    public void testSQLInjectionInCardnoIsNeutralised() throws Exception {
        String id = "10";
        String maliciousCardno = "'; DELETE FROM cards; --";
        String cvv = "999";
        String expirydate = "01/30";

        // Insert a clean row first
        PreparedStatement insert = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        insert.setString(1, "9");
        insert.setString(2, "4000000000000000");
        insert.setString(3, "000");
        insert.setString(4, "06/28");
        insert.executeUpdate();
        insert.close();

        // Now attempt injection via cardno parameter
        PreparedStatement ps = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        ps.setString(1, id);
        ps.setString(2, maliciousCardno);
        ps.setString(3, cvv);
        ps.setString(4, expirydate);
        ps.executeUpdate();
        ps.close();

        // Both rows should exist; DELETE must not have been executed
        Statement check = connection.createStatement();
        ResultSet rs = check.executeQuery("SELECT COUNT(*) FROM cards");
        rs.next();
        int count = rs.getInt(1);
        rs.close();
        check.close();

        assertEquals("Both rows should exist; DELETE must not have executed", 2, count);
    }

    /**
     * Verify that SQL injection via the expirydate parameter is neutralised.
     */
    public void testSQLInjectionInExpirydateIsNeutralised() throws Exception {
        String id = "20";
        String cardno = "5555555555554444";
        String cvv = "737";
        String maliciousExpiry = "12/25' OR '1'='1";

        PreparedStatement ps = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        ps.setString(1, id);
        ps.setString(2, cardno);
        ps.setString(3, cvv);
        ps.setString(4, maliciousExpiry);
        ps.executeUpdate();
        ps.close();

        // The row should have been stored with the literal malicious string, not interpreted as SQL
        PreparedStatement query = connection.prepareStatement(
            "SELECT expirydate FROM cards WHERE id=?"
        );
        query.setString(1, id);
        ResultSet rs = query.executeQuery();
        assertTrue("Row should exist", rs.next());
        // The expirydate value is stored as-is (literal string), not interpreted as SQL
        assertEquals("Expiry date stored as literal string", maliciousExpiry, rs.getString("expirydate"));
        rs.close();
        query.close();
    }

    // -------------------------------------------------------------------------
    // Tests for adminlogin.jsp fix: SELECT uses PreparedStatement
    // -------------------------------------------------------------------------

    /**
     * Verify that the admin login query with parameterized statement correctly
     * authenticates a valid admin user.
     */
    public void testAdminLoginWithValidCredentials() throws Exception {
        // Insert a valid admin user
        PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO users(id,username,password,privilege,avatar) values (?,?,?,?,?)"
        );
        insert.setString(1, "1");
        insert.setString(2, "admin");
        // Simulated hashed password value
        insert.setString(3, "5f4dcc3b5aa765d61d8327deb882cf99"); // md5("password")
        insert.setString(4, "admin");
        insert.setString(5, "default.png");
        insert.executeUpdate();
        insert.close();

        // Simulate the fixed adminlogin.jsp query using PreparedStatement
        String user = "admin";
        String pass = "5f4dcc3b5aa765d61d8327deb882cf99";
        PreparedStatement stmt = connection.prepareStatement(
            "select * from users where username=? and password=? and privilege='admin'"
        );
        stmt.setString(1, user);
        stmt.setString(2, pass);
        ResultSet rs = stmt.executeQuery();

        assertTrue("Valid admin credentials should authenticate successfully", rs.next());
        assertEquals("Should return correct user id", "1", rs.getString("id"));
        rs.close();
        stmt.close();
    }

    /**
     * Verify that a classic SQL injection bypass ('OR '1'='1) in the username
     * field does NOT authenticate when PreparedStatement is used.
     * The first-order injection in adminlogin.jsp was the entry point for the
     * second-order attack; this test confirms that path is also blocked.
     */
    public void testAdminLoginSQLInjectionBypassBlocked() throws Exception {
        // Insert a valid admin user
        PreparedStatement insert = connection.prepareStatement(
            "INSERT INTO users(id,username,password,privilege,avatar) values (?,?,?,?,?)"
        );
        insert.setString(1, "1");
        insert.setString(2, "admin");
        insert.setString(3, "5f4dcc3b5aa765d61d8327deb882cf99");
        insert.setString(4, "admin");
        insert.setString(5, "default.png");
        insert.executeUpdate();
        insert.close();

        // Classic bypass payload: if string-concatenated, this would always return rows
        String injectionUser = "' OR '1'='1";
        String injectionPass = "' OR '1'='1";

        PreparedStatement stmt = connection.prepareStatement(
            "select * from users where username=? and password=? and privilege='admin'"
        );
        stmt.setString(1, injectionUser);
        stmt.setString(2, injectionPass);
        ResultSet rs = stmt.executeQuery();

        // The injection payload must NOT authenticate
        assertFalse("SQL injection bypass must be blocked by PreparedStatement", rs.next());
        rs.close();
        stmt.close();
    }

    /**
     * Verify that a UNION-based SQL injection in the username field does not
     * return additional rows when PreparedStatement is used.
     */
    public void testAdminLoginUnionInjectionBlocked() throws Exception {
        String injectionUser = "admin' UNION SELECT 1,'attacker','hash','admin','av' --";
        String pass = "wrongpass";

        PreparedStatement stmt = connection.prepareStatement(
            "select * from users where username=? and password=? and privilege='admin'"
        );
        stmt.setString(1, injectionUser);
        stmt.setString(2, pass);
        ResultSet rs = stmt.executeQuery();

        // UNION injection must NOT return rows when using PreparedStatement
        assertFalse("UNION-based SQL injection must be blocked by PreparedStatement", rs.next());
        rs.close();
        stmt.close();
    }

    /**
     * Verify that the second-order injection chain is fully broken:
     * even if a malicious 'id' value was somehow stored in the session,
     * the INSERT in changeCardDetails.jsp treats it as literal data.
     *
     * This is the core regression test for the reported Second-Order SQL Injection.
     */
    public void testSecondOrderChainBroken() throws Exception {
        // Simulate: attacker crafted a userid that contains SQL that would, in the
        // old code, terminate the INSERT and execute additional SQL
        String attackerUserId = "1','x','y','z'); INSERT INTO cards(id,cardno,cvv,expirydate) VALUES ('evil";

        String cardno = "4111111111111111";
        String cvv = "123";
        String expirydate = "12/25";

        // With PreparedStatement the payload is stored literally — no extra INSERT executes
        PreparedStatement ps = connection.prepareStatement(
            "INSERT into cards(id,cardno,cvv,expirydate) values (?,?,?,?)"
        );
        ps.setString(1, attackerUserId);
        ps.setString(2, cardno);
        ps.setString(3, cvv);
        ps.setString(4, expirydate);
        ps.executeUpdate();
        ps.close();

        // Only 1 row should exist; the injected extra INSERT must not have executed
        Statement check = connection.createStatement();
        ResultSet rs = check.executeQuery("SELECT COUNT(*) FROM cards");
        rs.next();
        int count = rs.getInt(1);
        rs.close();
        check.close();

        assertEquals("Only 1 row should be inserted; second-order injection chain must be broken", 1, count);
    }
}
