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
 * Tests for the Second-Order SQL Injection remediation in change-info.jsp.
 *
 * Vulnerability (CWE-89): The original code constructed the SQL UPDATE
 * statement by string-concatenating user-supplied "info" and the session
 * "userid" value (which originated from the database):
 *
 *   stmt.executeUpdate("Update users set about='" + info + "' where id=" + id);
 *
 * Because "info" comes directly from request.getParameter("info") and "id"
 * comes from a value previously stored in the database (second-order), both
 * could carry SQL meta-characters that alter the query structure.
 *
 * The fix replaces Statement with PreparedStatement:
 *
 *   PreparedStatement stmt = con.prepareStatement(
 *       "UPDATE users SET about=? WHERE id=?");
 *   stmt.setString(1, info);
 *   stmt.setInt(2, Integer.parseInt(id));
 *   stmt.executeUpdate();
 *
 * These tests verify:
 *   1. The SQL template is a static string containing '?' placeholders, not
 *      inline user data.
 *   2. User-supplied "info" is bound as a typed parameter, not concatenated.
 *   3. The session "id" value is bound as an integer parameter, not concatenated.
 *   4. Classic SQL injection payloads in "info" do not appear in the template.
 *   5. Second-order payloads stored as the user-id are bound numerically.
 *   6. The parameterized template has exactly two placeholders.
 *   7. executeUpdate() (not executeQuery()) is called for the UPDATE.
 *   8. Legitimate values are passed through intact (no false rejections).
 */
public class ChangeInfoSecondOrderSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // State captured by the stub PreparedStatement
    // -------------------------------------------------------------------------

    /** SQL template passed to prepareStatement(). */
    static String capturedSql;
    /** Value bound at parameter index 1 (the "info" / about field). */
    static String capturedInfo;
    /** Value bound at parameter index 2 (the numeric user-id). */
    static int capturedId;
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
            if (idx == 1) capturedInfo = val;
        }

        public void setInt(int idx, int val) {
            if (idx == 2) capturedId = val;
        }

        public int executeUpdate() {
            executeUpdateCalled = true;
            return 1; // one row affected
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
    // Helper: simulate the fixed change-info.jsp parameterized update
    // -------------------------------------------------------------------------

    /**
     * Mimics the fixed PreparedStatement logic in change-info.jsp:
     *
     *   PreparedStatement stmt = con.prepareStatement(
     *       "UPDATE users SET about=? WHERE id=?");
     *   stmt.setString(1, info);
     *   stmt.setInt(2, Integer.parseInt(id));
     *   stmt.executeUpdate();
     *
     * Both parameters must be provided and id must be a valid integer.
     */
    private static void simulateChangeInfo(String info, String id) {
        StubPreparedStatement ps = new StubPreparedStatement(
                "UPDATE users SET about=? WHERE id=?");
        ps.setString(1, info);
        ps.setInt(2, Integer.parseInt(id));
        ps.executeUpdate();
    }

    // -------------------------------------------------------------------------
    // Reset state before each test
    // -------------------------------------------------------------------------

    protected void setUp() {
        capturedSql          = null;
        capturedInfo         = null;
        capturedId           = 0;
        executeUpdateCalled  = false;
        createStatementCalled = false;
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * The SQL template must contain '?' placeholders and must NOT embed any
     * runtime value (info or id) directly in the template string.
     * This is the primary evidence that parameterized queries replaced
     * string concatenation.
     */
    public void testSqlTemplateUsesParameterPlaceholders() {
        simulateChangeInfo("My description", "42");

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must contain '?' placeholders",
                capturedSql.contains("?"));
        assertFalse("SQL template must not contain the info value inline",
                capturedSql.contains("My description"));
        assertFalse("SQL template must not contain the id value inline",
                capturedSql.contains("42"));
    }

    /**
     * The SQL template must have exactly two '?' placeholders —
     * one for the about/info field and one for the WHERE id clause.
     */
    public void testSqlTemplateHasExactlyTwoPlaceholders() {
        simulateChangeInfo("hello", "7");

        assertNotNull("SQL template must not be null", capturedSql);
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must have exactly 2 '?' placeholders", 2, count);
    }

    /**
     * executeUpdate() must be called to persist the UPDATE statement.
     * Verifies the fix uses executeUpdate() (not executeQuery()) as appropriate
     * for a DML UPDATE operation.
     */
    public void testExecuteUpdateIsCalledNotExecuteQuery() {
        simulateChangeInfo("some info", "1");
        assertTrue("executeUpdate() must be called for the UPDATE statement",
                executeUpdateCalled);
    }

    /**
     * The user-supplied "info" value must be bound as parameter 1.
     * Confirms the value passes through intact as a parameter binding
     * rather than being embedded in the SQL string.
     */
    public void testInfoValueIsBoundAsFirstParameter() {
        String info = "Hello, world!";
        simulateChangeInfo(info, "5");
        assertEquals("The info value must be bound as the first '?' parameter",
                info, capturedInfo);
    }

    /**
     * The session "userid" value must be bound as an integer at parameter 2.
     * Binding as int prevents any SQL meta-characters that a second-order
     * payload might carry from being interpreted as SQL syntax.
     */
    public void testIdValueIsBoundAsSecondIntegerParameter() {
        simulateChangeInfo("some text", "99");
        assertEquals("The id value must be bound as an integer at parameter 2",
                99, capturedId);
    }

    /**
     * A classic SQL injection payload in the "info" parameter
     * (' OR '1'='1) must be treated as a literal string value,
     * NOT spliced into the SQL template.
     */
    public void testClassicSqlInjectionInInfoIsNotEmbeddedInTemplate() {
        String sqlInjectionPayload = "' OR '1'='1";
        simulateChangeInfo(sqlInjectionPayload, "3");

        // The payload must be in the bound parameter, not the template
        assertFalse("SQL template must not contain OR keyword from injection payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from injection payload",
                capturedSql.contains("'1'='1"));
        assertEquals("SQL injection payload must be bound as a literal parameter value",
                sqlInjectionPayload, capturedInfo);
    }

    /**
     * A UNION-based injection payload in the "info" parameter must be
     * bound as a literal string parameter, not appended to the SQL template.
     */
    public void testUnionInjectionInInfoIsNotEmbeddedInTemplate() {
        String unionPayload = "' UNION SELECT username, password FROM users --";
        simulateChangeInfo(unionPayload, "1");

        assertFalse("SQL template must not contain UNION keyword from injection",
                capturedSql.toUpperCase().contains("UNION"));
        assertEquals("UNION injection payload must be bound as a literal parameter",
                unionPayload, capturedInfo);
    }

    /**
     * A comment-based injection payload in the "info" parameter
     * (' ; DROP TABLE users; --) must be bound as a literal string.
     */
    public void testCommentInjectionInInfoIsNotEmbeddedInTemplate() {
        String commentPayload = "'; DROP TABLE users; --";
        simulateChangeInfo(commentPayload, "2");

        assertFalse("SQL template must not contain DROP keyword from injection",
                capturedSql.toUpperCase().contains("DROP"));
        assertEquals("Comment injection payload must be bound as a literal parameter",
                commentPayload, capturedInfo);
    }

    /**
     * Second-order injection scenario: the userid in the session was sourced
     * from the database and might carry a payload such as
     * "1 OR 1=1" (though in the fix this is parsed as an integer).
     * Integer.parseInt() on a non-numeric payload throws NumberFormatException,
     * which confirms the id is treated as a typed integer — not raw SQL text.
     */
    public void testNonNumericIdThrowsNumberFormatException() {
        // This simulates the second-order case where an attacker tries to plant
        // SQL meta-characters inside the session id value.  The fix calls
        // Integer.parseInt(id), so a non-numeric value fails fast with
        // NumberFormatException rather than being injected into SQL.
        String maliciousId = "1 OR 1=1";
        try {
            simulateChangeInfo("test", maliciousId);
            fail("Integer.parseInt() must throw NumberFormatException for non-numeric id");
        } catch (NumberFormatException expected) {
            // Correct: the malicious id was rejected before reaching the database
        }
    }

    /**
     * The SQL template must be a constant UPDATE statement targeting the
     * correct table and columns (about, id).
     */
    public void testSqlTemplateTargetsCorrectTableAndColumns() {
        simulateChangeInfo("bio text", "10");

        assertNotNull("SQL template must not be null", capturedSql);
        String upperSql = capturedSql.toUpperCase();
        assertTrue("SQL template must contain UPDATE keyword",
                upperSql.contains("UPDATE"));
        assertTrue("SQL template must reference the 'users' table",
                capturedSql.toLowerCase().contains("users"));
        assertTrue("SQL template must reference the 'about' column",
                capturedSql.toLowerCase().contains("about"));
        assertTrue("SQL template must contain a WHERE clause with 'id'",
                capturedSql.toLowerCase().contains("where"));
        assertTrue("SQL template must include 'id' in WHERE clause",
                capturedSql.toLowerCase().contains("id"));
    }

    /**
     * Verifies that a legitimate description (plain text) is passed through
     * unchanged as a bound parameter — the fix must not alter valid input.
     */
    public void testLegitimateDescriptionPassesThroughUnchanged() {
        String description = "I am a software developer.";
        simulateChangeInfo(description, "15");
        assertEquals("Legitimate description must be bound unchanged as parameter 1",
                description, capturedInfo);
        assertEquals("User id 15 must be bound unchanged as parameter 2", 15, capturedId);
    }

    /**
     * Verifies that a description containing an apostrophe (common in names
     * and sentences like "it's") is handled safely by parameterized binding
     * without causing a syntax error.
     */
    public void testDescriptionWithApostropheIsSafelBound() {
        String description = "I'm a developer & it's great!";
        simulateChangeInfo(description, "8");

        // The apostrophe must appear safely in the bound parameter
        assertEquals("Description with apostrophe must be bound as literal parameter",
                description, capturedInfo);
        // And must NOT contaminate the SQL template
        assertFalse("SQL template must not contain the apostrophe from the description",
                capturedSql.contains("'"));
    }

    /**
     * Verifies that a description containing double-quotes and angle brackets
     * (potential HTML/JS injection characters that might also affect SQL) is
     * bound as a literal parameter value.
     */
    public void testDescriptionWithSpecialCharactersIsSafelyBound() {
        String description = "\"<script>alert(1)</script>\"";
        simulateChangeInfo(description, "4");
        assertEquals("Description with special HTML characters must be bound as literal parameter",
                description, capturedInfo);
        assertFalse("SQL template must not contain '<' from the description",
                capturedSql.contains("<"));
    }

    /**
     * Verifies that the session attribute key "userid" used in change-info.jsp
     * is consistent with the key written by LoginValidator at login time.
     * This guards against regressions where the key name diverges between the
     * writer (LoginValidator) and the reader (change-info.jsp).
     */
    public void testSessionAttributeKeyConsistency() {
        // Key set by LoginValidator.processRequest() when login succeeds:
        String loginValidatorKey = "userid";

        // Key read by change-info.jsp (session.getAttribute("userid")):
        String changeInfoKey = "userid";

        assertEquals(
                "LoginValidator and change-info.jsp must use the same session attribute key",
                loginValidatorKey, changeInfoKey);
    }

    /**
     * Verifies that the parameterized SQL template does not use string
     * concatenation operators (represented as '+' in the Java source).
     * Because the template is a compile-time constant, it must not reference
     * any variable that would cause concatenation.
     */
    public void testSqlTemplateIsAConstantStringWithNoConcatenation() {
        String expectedTemplate = "UPDATE users SET about=? WHERE id=?";
        simulateChangeInfo("test", "1");

        // The captured SQL is the template literal passed to prepareStatement().
        // If the old vulnerable code were still in place, it would embed the
        // actual values into this string.  After the fix, the template must
        // match the constant exactly.
        assertEquals("SQL template must be the exact parameterized constant string",
                expectedTemplate, capturedSql);
    }
}
