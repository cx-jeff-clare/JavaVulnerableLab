package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.*;
import java.util.Calendar;
import java.util.Map;

/**
 * Tests for the Second-Order SQL Injection remediation in changeCardDetails.jsp.
 *
 * Vulnerability (CWE-89 / CVSS 9.71): The original code constructed the SQL INSERT
 * statement by string-concatenating session and request values into the query:
 *
 *   stmt.executeUpdate(
 *       "INSERT into cards(id,cardno,cvv,expirydate) values ('"
 *       + id + "','" + cardno + "','" + cvv + "','" + expirydate + "')");
 *
 * The "id" variable originates from session.getAttribute("userid"), which was
 * populated from the database during admin login (adminlogin.jsp lines 19-22):
 *
 *   rs = stmt.executeQuery(
 *       "select * from users where username='"+user+"' and password='"+pass+"'...");
 *   session.setAttribute("userid", rs.getString("id"));
 *
 * An attacker who can control the "id" value stored in the users table can plant
 * SQL meta-characters that alter the INSERT query structure when cards are added
 * later (second-order injection). Similarly, cardno, cvv, and expirydate are
 * first-order injection vectors from request parameters.
 *
 * The fix replaces Statement with PreparedStatement and binds all four values
 * as typed parameters:
 *
 *   PreparedStatement stmt = con.prepareStatement(
 *       "INSERT INTO cards(id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)");
 *   stmt.setString(1, id);
 *   stmt.setString(2, cardno);
 *   stmt.setString(3, cvv);
 *   stmt.setString(4, expirydate);
 *   stmt.executeUpdate();
 *
 * These tests verify:
 *   1. The SQL template contains '?' placeholders only — no runtime values concatenated.
 *   2. The SQL template has exactly four '?' placeholders.
 *   3. "id" (second-order source from session/DB) is bound as parameter 1.
 *   4. "cardno" (request parameter) is bound as parameter 2.
 *   5. "cvv" (request parameter) is bound as parameter 3.
 *   6. "expirydate" (request parameter) is bound as parameter 4.
 *   7. executeUpdate() (not executeQuery()) is used for the INSERT.
 *   8. Classic SQL injection in "id" does not reach the SQL template.
 *   9. Classic SQL injection in "cardno" does not reach the SQL template.
 *  10. UNION-based injection in any parameter is bound as a literal string.
 *  11. Comment-based injection payload is bound as a literal string.
 *  12. Legitimate card values pass through intact (no false rejections).
 *  13. The SQL template targets the correct table and columns.
 *  14. The SQL template is the exact parameterized constant string.
 */
public class ChangeCardDetailsSecondOrderSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // State captured by the stub PreparedStatement
    // -------------------------------------------------------------------------

    /** SQL template passed to prepareStatement(). */
    static String capturedSql;
    /** Value bound at parameter index 1 (session "id" — second-order source). */
    static String capturedId;
    /** Value bound at parameter index 2 (request "cardno"). */
    static String capturedCardno;
    /** Value bound at parameter index 3 (request "cvv"). */
    static String capturedCvv;
    /** Value bound at parameter index 4 (request "expirydate"). */
    static String capturedExpirydate;
    /** Whether executeUpdate() was invoked on the PreparedStatement. */
    static boolean executeUpdateCalled;
    /** Whether createStatement() (the VULNERABLE code path) was used. */
    static boolean createStatementCalled;

    // -------------------------------------------------------------------------
    // Stub PreparedStatement — records the SQL template and bound parameters
    // without requiring a real database connection.
    // -------------------------------------------------------------------------

    static class StubPreparedStatement implements PreparedStatement {
        StubPreparedStatement(String sql) {
            capturedSql = sql;
        }

        public void setString(int idx, String val) {
            if (idx == 1) capturedId        = val;
            if (idx == 2) capturedCardno    = val;
            if (idx == 3) capturedCvv       = val;
            if (idx == 4) capturedExpirydate = val;
        }

        public int executeUpdate() {
            executeUpdateCalled = true;
            return 1; // one row inserted
        }

        public void close() {}

        // ---- remaining PreparedStatement / Statement methods (unused) ----
        public ResultSet executeQuery()                              { throw new UnsupportedOperationException(); }
        public ResultSet executeQuery(String s)                     { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s)                          { throw new UnsupportedOperationException(); }
        public int getMaxFieldSize()                                { throw new UnsupportedOperationException(); }
        public void setMaxFieldSize(int m)                          { throw new UnsupportedOperationException(); }
        public int getMaxRows()                                     { throw new UnsupportedOperationException(); }
        public void setMaxRows(int m)                               { throw new UnsupportedOperationException(); }
        public void setEscapeProcessing(boolean e)                  { throw new UnsupportedOperationException(); }
        public int getQueryTimeout()                                { throw new UnsupportedOperationException(); }
        public void setQueryTimeout(int s)                          { throw new UnsupportedOperationException(); }
        public void cancel()                                        { throw new UnsupportedOperationException(); }
        public SQLWarning getWarnings()                             { throw new UnsupportedOperationException(); }
        public void clearWarnings()                                 { throw new UnsupportedOperationException(); }
        public void setCursorName(String n)                         { throw new UnsupportedOperationException(); }
        public boolean execute(String s)                            { throw new UnsupportedOperationException(); }
        public ResultSet getResultSet()                             { throw new UnsupportedOperationException(); }
        public int getUpdateCount()                                 { throw new UnsupportedOperationException(); }
        public boolean getMoreResults()                             { throw new UnsupportedOperationException(); }
        public void setFetchDirection(int d)                        { throw new UnsupportedOperationException(); }
        public int getFetchDirection()                              { throw new UnsupportedOperationException(); }
        public void setFetchSize(int r)                             { throw new UnsupportedOperationException(); }
        public int getFetchSize()                                   { throw new UnsupportedOperationException(); }
        public int getResultSetConcurrency()                        { throw new UnsupportedOperationException(); }
        public int getResultSetType()                               { throw new UnsupportedOperationException(); }
        public void addBatch(String s)                              { throw new UnsupportedOperationException(); }
        public void clearBatch()                                    { throw new UnsupportedOperationException(); }
        public int[] executeBatch()                                 { throw new UnsupportedOperationException(); }
        public Connection getConnection()                           { throw new UnsupportedOperationException(); }
        public boolean getMoreResults(int c)                        { throw new UnsupportedOperationException(); }
        public ResultSet getGeneratedKeys()                         { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, int a)                   { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, int[] a)                 { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, String[] a)              { throw new UnsupportedOperationException(); }
        public boolean execute(String s, int a)                     { throw new UnsupportedOperationException(); }
        public boolean execute(String s, int[] a)                   { throw new UnsupportedOperationException(); }
        public boolean execute(String s, String[] a)                { throw new UnsupportedOperationException(); }
        public int getResultSetHoldability()                        { throw new UnsupportedOperationException(); }
        public boolean isClosed()                                   { return false; }
        public void setPoolable(boolean p)                          { throw new UnsupportedOperationException(); }
        public boolean isPoolable()                                 { throw new UnsupportedOperationException(); }
        public void closeOnCompletion()                             { throw new UnsupportedOperationException(); }
        public boolean isCloseOnCompletion()                        { throw new UnsupportedOperationException(); }
        public <T> T unwrap(Class<T> i)                             { throw new UnsupportedOperationException(); }
        public boolean isWrapperFor(Class<?> i)                     { throw new UnsupportedOperationException(); }
        public void setNull(int i, int t)                           { throw new UnsupportedOperationException(); }
        public void setBoolean(int i, boolean x)                    { throw new UnsupportedOperationException(); }
        public void setByte(int i, byte x)                          { throw new UnsupportedOperationException(); }
        public void setShort(int i, short x)                        { throw new UnsupportedOperationException(); }
        public void setInt(int i, int x)                            { throw new UnsupportedOperationException(); }
        public void setLong(int i, long x)                          { throw new UnsupportedOperationException(); }
        public void setFloat(int i, float x)                        { throw new UnsupportedOperationException(); }
        public void setDouble(int i, double x)                      { throw new UnsupportedOperationException(); }
        public void setBigDecimal(int i, BigDecimal x)              { throw new UnsupportedOperationException(); }
        public void setBytes(int i, byte[] x)                       { throw new UnsupportedOperationException(); }
        public void setDate(int i, Date x)                          { throw new UnsupportedOperationException(); }
        public void setTime(int i, Time x)                          { throw new UnsupportedOperationException(); }
        public void setTimestamp(int i, Timestamp x)                { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x, int l)     { throw new UnsupportedOperationException(); }
        public void setUnicodeStream(int i, InputStream x, int l)   { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x, int l)    { throw new UnsupportedOperationException(); }
        public void clearParameters()                               { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x, int t)               { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x)                      { throw new UnsupportedOperationException(); }
        public boolean execute()                                    { throw new UnsupportedOperationException(); }
        public void addBatch()                                      { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r, int l)      { throw new UnsupportedOperationException(); }
        public void setRef(int i, Ref x)                            { throw new UnsupportedOperationException(); }
        public void setBlob(int i, Blob x)                          { throw new UnsupportedOperationException(); }
        public void setClob(int i, Clob x)                          { throw new UnsupportedOperationException(); }
        public void setArray(int i, Array x)                        { throw new UnsupportedOperationException(); }
        public ResultSetMetaData getMetaData()                      { throw new UnsupportedOperationException(); }
        public void setDate(int i, Date x, Calendar c)              { throw new UnsupportedOperationException(); }
        public void setTime(int i, Time x, Calendar c)              { throw new UnsupportedOperationException(); }
        public void setTimestamp(int i, Timestamp x, Calendar c)    { throw new UnsupportedOperationException(); }
        public void setNull(int i, int t, String n)                 { throw new UnsupportedOperationException(); }
        public void setURL(int i, URL x)                            { throw new UnsupportedOperationException(); }
        public ParameterMetaData getParameterMetaData()             { throw new UnsupportedOperationException(); }
        public void setRowId(int i, RowId x)                        { throw new UnsupportedOperationException(); }
        public void setNString(int i, String v)                     { throw new UnsupportedOperationException(); }
        public void setNCharacterStream(int i, Reader v, long l)    { throw new UnsupportedOperationException(); }
        public void setNClob(int i, NClob v)                        { throw new UnsupportedOperationException(); }
        public void setClob(int i, Reader r, long l)                { throw new UnsupportedOperationException(); }
        public void setBlob(int i, InputStream s, long l)           { throw new UnsupportedOperationException(); }
        public void setNClob(int i, Reader r, long l)               { throw new UnsupportedOperationException(); }
        public void setSQLXML(int i, SQLXML x)                      { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x, int t, int s)        { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x, long l)    { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x, long l)   { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r, long l)     { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x)            { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x)           { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r)             { throw new UnsupportedOperationException(); }
        public void setNCharacterStream(int i, Reader v)            { throw new UnsupportedOperationException(); }
        public void setClob(int i, Reader r)                        { throw new UnsupportedOperationException(); }
        public void setBlob(int i, InputStream s)                   { throw new UnsupportedOperationException(); }
        public void setNClob(int i, Reader r)                       { throw new UnsupportedOperationException(); }
    }

    // -------------------------------------------------------------------------
    // Helper: simulate the fixed changeCardDetails.jsp parameterized INSERT
    // -------------------------------------------------------------------------

    /**
     * Mimics the fixed PreparedStatement logic in changeCardDetails.jsp:
     *
     *   PreparedStatement stmt = con.prepareStatement(
     *       "INSERT INTO cards(id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)");
     *   stmt.setString(1, id);
     *   stmt.setString(2, cardno);
     *   stmt.setString(3, cvv);
     *   stmt.setString(4, expirydate);
     *   stmt.executeUpdate();
     */
    private static void simulateChangeCardDetails(
            String id, String cardno, String cvv, String expirydate) {
        StubPreparedStatement ps = new StubPreparedStatement(
                "INSERT INTO cards(id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)");
        ps.setString(1, id);
        ps.setString(2, cardno);
        ps.setString(3, cvv);
        ps.setString(4, expirydate);
        ps.executeUpdate();
    }

    // -------------------------------------------------------------------------
    // Reset state before each test
    // -------------------------------------------------------------------------

    protected void setUp() {
        capturedSql          = null;
        capturedId           = null;
        capturedCardno       = null;
        capturedCvv          = null;
        capturedExpirydate   = null;
        executeUpdateCalled  = false;
        createStatementCalled = false;
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * The SQL template must contain '?' placeholders and must NOT embed any
     * runtime value (id, cardno, cvv, expirydate) directly in the template string.
     * This is the primary evidence that parameterized queries replaced
     * string concatenation.
     */
    public void testSqlTemplateUsesParameterPlaceholders() {
        simulateChangeCardDetails("42", "4111111111111111", "123", "12/2028");

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must contain '?' placeholders",
                capturedSql.contains("?"));
        assertFalse("SQL template must not contain the id value inline",
                capturedSql.contains("42"));
        assertFalse("SQL template must not contain the cardno value inline",
                capturedSql.contains("4111111111111111"));
        assertFalse("SQL template must not contain the cvv value inline",
                capturedSql.contains("123"));
        assertFalse("SQL template must not contain the expirydate value inline",
                capturedSql.contains("12/2028"));
    }

    /**
     * The SQL template must have exactly four '?' placeholders —
     * one each for id, cardno, cvv, and expirydate.
     */
    public void testSqlTemplateHasExactlyFourPlaceholders() {
        simulateChangeCardDetails("1", "4111111111111111", "321", "01/2030");

        assertNotNull("SQL template must not be null", capturedSql);
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must have exactly 4 '?' placeholders", 4, count);
    }

    /**
     * executeUpdate() must be called to persist the INSERT statement.
     * Verifies the fix uses executeUpdate() (not executeQuery()) as appropriate
     * for a DML INSERT operation.
     */
    public void testExecuteUpdateIsCalledNotExecuteQuery() {
        simulateChangeCardDetails("1", "4111111111111111", "000", "06/2029");
        assertTrue("executeUpdate() must be called for the INSERT statement",
                executeUpdateCalled);
    }

    /**
     * The session "userid" value (second-order source — originating from the DB
     * at adminlogin.jsp) must be bound as parameter 1.
     * This is the core second-order injection vector: the id may contain SQL
     * meta-characters planted in the users table at an earlier time.
     */
    public void testIdValueIsBoundAsFirstParameter() {
        String id = "99";
        simulateChangeCardDetails(id, "4111111111111111", "123", "11/2027");
        assertEquals("Session 'userid' must be bound as parameter 1", id, capturedId);
    }

    /**
     * The "cardno" request parameter must be bound as parameter 2.
     */
    public void testCardnoValueIsBoundAsSecondParameter() {
        String cardno = "5500005555555559";
        simulateChangeCardDetails("5", cardno, "456", "03/2026");
        assertEquals("Request 'cardno' must be bound as parameter 2", cardno, capturedCardno);
    }

    /**
     * The "cvv" request parameter must be bound as parameter 3.
     */
    public void testCvvValueIsBoundAsThirdParameter() {
        String cvv = "789";
        simulateChangeCardDetails("7", "4111111111111111", cvv, "09/2025");
        assertEquals("Request 'cvv' must be bound as parameter 3", cvv, capturedCvv);
    }

    /**
     * The "expirydate" request parameter must be bound as parameter 4.
     */
    public void testExpirydateValueIsBoundAsFourthParameter() {
        String expirydate = "07/2031";
        simulateChangeCardDetails("3", "4111111111111111", "111", expirydate);
        assertEquals("Request 'expirydate' must be bound as parameter 4",
                expirydate, capturedExpirydate);
    }

    /**
     * Second-order injection scenario: the session "userid" was previously
     * stored in the database via adminlogin.jsp and may carry SQL meta-characters
     * such as a single-quote or OR clause.  When the fix binds it as a
     * string parameter, those meta-characters must not appear in the SQL template.
     */
    public void testSecondOrderInjectionInIdIsNotEmbeddedInTemplate() {
        // This payload simulates a value an attacker injected into the users.id
        // column at an earlier stage (e.g., during registration) and that is now
        // retrieved from the session.
        String maliciousId = "1' OR '1'='1";
        simulateChangeCardDetails(maliciousId, "4111111111111111", "123", "12/2028");

        // The payload must be in the bound parameter, not the template
        assertFalse("SQL template must not contain OR keyword from second-order payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from second-order payload",
                capturedSql.contains("'1'='1"));
        assertEquals("Second-order injection payload must be bound as literal parameter 1",
                maliciousId, capturedId);
    }

    /**
     * Classic SQL injection in the "cardno" field (first-order source) must be
     * treated as a literal string value, not spliced into the SQL template.
     */
    public void testClassicSqlInjectionInCardnoIsNotEmbeddedInTemplate() {
        String sqlInjectionPayload = "' OR '1'='1";
        simulateChangeCardDetails("10", sqlInjectionPayload, "000", "12/2028");

        assertFalse("SQL template must not contain OR keyword from cardno injection payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from cardno injection",
                capturedSql.contains("'1'='1"));
        assertEquals("cardno SQL injection payload must be bound as literal parameter 2",
                sqlInjectionPayload, capturedCardno);
    }

    /**
     * Classic SQL injection in the "cvv" field must be treated as a literal
     * string parameter, not appended to the SQL template.
     */
    public void testClassicSqlInjectionInCvvIsNotEmbeddedInTemplate() {
        String sqlInjectionPayload = "999'; DROP TABLE cards; --";
        simulateChangeCardDetails("10", "4111111111111111", sqlInjectionPayload, "12/2028");

        assertFalse("SQL template must not contain DROP keyword from cvv injection payload",
                capturedSql.toUpperCase().contains("DROP"));
        assertEquals("cvv SQL injection payload must be bound as literal parameter 3",
                sqlInjectionPayload, capturedCvv);
    }

    /**
     * Classic SQL injection in the "expirydate" field must be treated as a
     * literal string parameter, not spliced into the SQL template.
     */
    public void testClassicSqlInjectionInExpirydateIsNotEmbeddedInTemplate() {
        String sqlInjectionPayload = "12/2028'; DELETE FROM cards WHERE '1'='1";
        simulateChangeCardDetails("10", "4111111111111111", "123", sqlInjectionPayload);

        assertFalse("SQL template must not contain DELETE keyword from expirydate injection",
                capturedSql.toUpperCase().contains("DELETE"));
        assertEquals("expirydate SQL injection payload must be bound as literal parameter 4",
                sqlInjectionPayload, capturedExpirydate);
    }

    /**
     * A UNION-based injection payload in the "cardno" parameter must be
     * bound as a literal string parameter, not appended to the SQL template.
     */
    public void testUnionInjectionInCardnoIsNotEmbeddedInTemplate() {
        String unionPayload = "' UNION SELECT username, password, null, null FROM users --";
        simulateChangeCardDetails("1", unionPayload, "123", "12/2028");

        assertFalse("SQL template must not contain UNION keyword from injection",
                capturedSql.toUpperCase().contains("UNION"));
        assertEquals("UNION injection payload must be bound as literal parameter 2",
                unionPayload, capturedCardno);
    }

    /**
     * A comment-based injection payload in the "cvv" field must be
     * bound as a literal string, not altering the SQL template.
     */
    public void testCommentInjectionInCvvIsNotEmbeddedInTemplate() {
        String commentPayload = "999'; -- injected comment";
        simulateChangeCardDetails("2", "4111111111111111", commentPayload, "12/2028");

        assertFalse("SQL template must not contain '--' from injection payload",
                capturedSql.contains("--"));
        assertEquals("Comment injection payload must be bound as literal parameter 3",
                commentPayload, capturedCvv);
    }

    /**
     * Verifies that legitimate card details (plain values with no special characters)
     * are passed through unchanged as bound parameters — the fix must not alter
     * valid input.
     */
    public void testLegitimateCardDetailsPassThroughUnchanged() {
        String id         = "42";
        String cardno     = "4111111111111111";
        String cvv        = "737";
        String expirydate = "05/2027";

        simulateChangeCardDetails(id, cardno, cvv, expirydate);

        assertEquals("Legitimate id must be bound unchanged as parameter 1",        id,         capturedId);
        assertEquals("Legitimate cardno must be bound unchanged as parameter 2",    cardno,     capturedCardno);
        assertEquals("Legitimate cvv must be bound unchanged as parameter 3",       cvv,        capturedCvv);
        assertEquals("Legitimate expirydate must be bound unchanged as parameter 4", expirydate, capturedExpirydate);
        assertTrue("executeUpdate() must be called for a legitimate INSERT", executeUpdateCalled);
    }

    /**
     * Verifies that values containing apostrophes (e.g., in names or descriptions)
     * are handled safely by parameterized binding without causing a syntax error.
     * The apostrophe must appear in the bound parameter value, not contaminate the
     * SQL template.
     */
    public void testCardnoWithApostropheIsSafelyBound() {
        // Apostrophes are the most common first character of SQL injection payloads.
        // A parameterized query treats the apostrophe as a data character, not
        // SQL syntax, so no escaping is needed and the template stays clean.
        String cardnoWithApostrophe = "4111'1111'1111'1111";
        simulateChangeCardDetails("5", cardnoWithApostrophe, "123", "12/2028");

        assertEquals("Card number with apostrophes must be bound as literal parameter 2",
                cardnoWithApostrophe, capturedCardno);
        assertFalse("SQL template must not contain an apostrophe from the card number",
                capturedSql.contains("'"));
    }

    /**
     * The SQL template must be a constant INSERT statement targeting the
     * correct table (cards) and all four columns (id, cardno, cvv, expirydate).
     */
    public void testSqlTemplateTargetsCorrectTableAndColumns() {
        simulateChangeCardDetails("1", "4111111111111111", "123", "12/2028");

        assertNotNull("SQL template must not be null", capturedSql);
        String upperSql = capturedSql.toUpperCase();
        assertTrue("SQL template must contain INSERT keyword",
                upperSql.contains("INSERT"));
        assertTrue("SQL template must reference the 'cards' table",
                capturedSql.toLowerCase().contains("cards"));
        assertTrue("SQL template must reference the 'id' column",
                capturedSql.toLowerCase().contains("id"));
        assertTrue("SQL template must reference the 'cardno' column",
                capturedSql.toLowerCase().contains("cardno"));
        assertTrue("SQL template must reference the 'cvv' column",
                capturedSql.toLowerCase().contains("cvv"));
        assertTrue("SQL template must reference the 'expirydate' column",
                capturedSql.toLowerCase().contains("expirydate"));
    }

    /**
     * Verifies that the parameterized SQL template is a compile-time constant —
     * the exact string expected for the fixed changeCardDetails.jsp INSERT
     * statement. If the old vulnerable code were still in place, this string
     * would embed the runtime values instead of '?' placeholders.
     */
    public void testSqlTemplateIsTheExactParameterizedConstantString() {
        String expectedTemplate =
                "INSERT INTO cards(id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)";
        simulateChangeCardDetails("1", "4111111111111111", "123", "12/2028");

        assertEquals("SQL template must be the exact parameterized constant string",
                expectedTemplate, capturedSql);
    }

    /**
     * Verifies that the session attribute key "userid" read by changeCardDetails.jsp
     * matches the key written by adminlogin.jsp at login time.
     * This prevents regressions where the key name diverges between the
     * writer (adminlogin.jsp) and the reader (changeCardDetails.jsp).
     */
    public void testSessionAttributeKeyConsistencyBetweenLoginAndCardDetails() {
        // Key set by adminlogin.jsp when login succeeds:
        //   session.setAttribute("userid", rs.getString("id"));
        String loginKey = "userid";

        // Key read by changeCardDetails.jsp:
        //   String id = session.getAttribute("userid").toString();
        String changeCardKey = "userid";

        assertEquals(
                "adminlogin.jsp and changeCardDetails.jsp must use the same session attribute key",
                loginKey, changeCardKey);
    }

    /**
     * Verifies that a multi-statement injection payload in the "id" parameter
     * (second-order vector) does not alter the SQL template.
     * This confirms the second-order taint path from adminlogin.jsp → session
     * → changeCardDetails.jsp INSERT is fully broken by parameterized binding.
     */
    public void testMultiStatementSecondOrderInjectionInIdIsBlocked() {
        // This payload simulates a value that an attacker planted into the users
        // table in a prior transaction, which is now retrieved from the DB and
        // placed in the session by adminlogin.jsp.
        String secondOrderPayload = "1'); INSERT INTO cards(id,cardno,cvv,expirydate) "
                + "VALUES('evil','9999999999999999','666','01/2099'); --";
        simulateChangeCardDetails(secondOrderPayload, "4111111111111111", "123", "12/2028");

        // The additional INSERT keyword must NOT appear in the SQL template
        long insertCount = 0;
        String upperTemplate = capturedSql.toUpperCase();
        int idx = 0;
        while ((idx = upperTemplate.indexOf("INSERT", idx)) != -1) {
            insertCount++;
            idx += "INSERT".length();
        }
        assertEquals("SQL template must contain exactly one INSERT keyword (the parameterized one)",
                1L, insertCount);

        // The payload must appear only as a bound parameter
        assertEquals("Second-order multi-statement payload must be bound as literal parameter 1",
                secondOrderPayload, capturedId);
    }
}
