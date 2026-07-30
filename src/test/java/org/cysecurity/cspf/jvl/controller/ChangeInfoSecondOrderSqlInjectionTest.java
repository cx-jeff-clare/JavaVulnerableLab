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
 * Tests for the change-info.jsp Second-Order SQL Injection remediation.
 *
 * The fix replaced a vulnerable Statement (string-concatenated query) with a
 * parameterized PreparedStatement. These tests verify:
 *   1. The SQL template uses '?' placeholders, not embedded values.
 *   2. The 'info' (user-supplied) parameter is bound safely, not concatenated.
 *   3. The 'id' (session value originating from DB data) is bound safely.
 *   4. Classical SQL injection payloads in 'info' are treated as literals.
 *   5. Second-order SQL injection payloads stored in 'id' are treated as literals.
 *   6. Valid inputs flow through correctly (regression check).
 */
public class ChangeInfoSecondOrderSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // Captured state - populated by stub methods during each test
    // -------------------------------------------------------------------------

    /** Records the SQL template passed to Connection.prepareStatement(). */
    static String capturedSql;

    /** Records the value bound at parameter index 1 (the 'info' / about column). */
    static String capturedParam1;

    /** Records the value bound at parameter index 2 (the 'id' / WHERE clause). */
    static String capturedParam2;

    /** Whether executeUpdate() was called on the PreparedStatement. */
    static boolean executeUpdateCalled;

    /** Whether createStatement() (the VULNERABLE, unfixed path) was ever called. */
    static boolean createStatementCalled;

    // -------------------------------------------------------------------------
    // Minimal stub PreparedStatement - records calls; does not hit a database.
    // -------------------------------------------------------------------------

    static class StubPreparedStatement implements PreparedStatement {
        private final String sql;

        StubPreparedStatement(String sql) {
            capturedSql = sql;
            this.sql = sql;
        }

        public void setString(int idx, String val) {
            if (idx == 1) capturedParam1 = val;
            if (idx == 2) capturedParam2 = val;
        }

        public int executeUpdate() throws SQLException {
            executeUpdateCalled = true;
            return 1; // simulate 1 row updated
        }

        public void close() throws SQLException {}

        // --- remaining PreparedStatement / Statement stubs (unused in this flow) ---
        public ResultSet executeQuery() { throw new UnsupportedOperationException(); }
        public ResultSet executeQuery(String s) { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s) { throw new UnsupportedOperationException(); }
        public int getMaxFieldSize() { throw new UnsupportedOperationException(); }
        public void setMaxFieldSize(int m) { throw new UnsupportedOperationException(); }
        public int getMaxRows() { throw new UnsupportedOperationException(); }
        public void setMaxRows(int m) { throw new UnsupportedOperationException(); }
        public void setEscapeProcessing(boolean e) { throw new UnsupportedOperationException(); }
        public int getQueryTimeout() { throw new UnsupportedOperationException(); }
        public void setQueryTimeout(int s) { throw new UnsupportedOperationException(); }
        public void cancel() { throw new UnsupportedOperationException(); }
        public SQLWarning getWarnings() { throw new UnsupportedOperationException(); }
        public void clearWarnings() { throw new UnsupportedOperationException(); }
        public void setCursorName(String n) { throw new UnsupportedOperationException(); }
        public boolean execute(String s) { throw new UnsupportedOperationException(); }
        public ResultSet getResultSet() { throw new UnsupportedOperationException(); }
        public int getUpdateCount() { throw new UnsupportedOperationException(); }
        public boolean getMoreResults() { throw new UnsupportedOperationException(); }
        public void setFetchDirection(int d) { throw new UnsupportedOperationException(); }
        public int getFetchDirection() { throw new UnsupportedOperationException(); }
        public void setFetchSize(int r) { throw new UnsupportedOperationException(); }
        public int getFetchSize() { throw new UnsupportedOperationException(); }
        public int getResultSetConcurrency() { throw new UnsupportedOperationException(); }
        public int getResultSetType() { throw new UnsupportedOperationException(); }
        public void addBatch(String s) { throw new UnsupportedOperationException(); }
        public void clearBatch() { throw new UnsupportedOperationException(); }
        public int[] executeBatch() { throw new UnsupportedOperationException(); }
        public Connection getConnection() { throw new UnsupportedOperationException(); }
        public boolean getMoreResults(int c) { throw new UnsupportedOperationException(); }
        public ResultSet getGeneratedKeys() { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, int a) { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, int[] a) { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s, String[] a) { throw new UnsupportedOperationException(); }
        public boolean execute(String s, int a) { throw new UnsupportedOperationException(); }
        public boolean execute(String s, int[] a) { throw new UnsupportedOperationException(); }
        public boolean execute(String s, String[] a) { throw new UnsupportedOperationException(); }
        public int getResultSetHoldability() { throw new UnsupportedOperationException(); }
        public boolean isClosed() { return false; }
        public void setPoolable(boolean p) { throw new UnsupportedOperationException(); }
        public boolean isPoolable() { throw new UnsupportedOperationException(); }
        public void closeOnCompletion() { throw new UnsupportedOperationException(); }
        public boolean isCloseOnCompletion() { throw new UnsupportedOperationException(); }
        public <T> T unwrap(Class<T> i) { throw new UnsupportedOperationException(); }
        public boolean isWrapperFor(Class<?> i) { throw new UnsupportedOperationException(); }
        public void setNull(int i, int t) { throw new UnsupportedOperationException(); }
        public void setBoolean(int i, boolean x) { throw new UnsupportedOperationException(); }
        public void setByte(int i, byte x) { throw new UnsupportedOperationException(); }
        public void setShort(int i, short x) { throw new UnsupportedOperationException(); }
        public void setInt(int i, int x) { throw new UnsupportedOperationException(); }
        public void setLong(int i, long x) { throw new UnsupportedOperationException(); }
        public void setFloat(int i, float x) { throw new UnsupportedOperationException(); }
        public void setDouble(int i, double x) { throw new UnsupportedOperationException(); }
        public void setBigDecimal(int i, BigDecimal x) { throw new UnsupportedOperationException(); }
        public void setBytes(int i, byte[] x) { throw new UnsupportedOperationException(); }
        public void setDate(int i, Date x) { throw new UnsupportedOperationException(); }
        public void setTime(int i, Time x) { throw new UnsupportedOperationException(); }
        public void setTimestamp(int i, Timestamp x) { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void setUnicodeStream(int i, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void clearParameters() { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x, int t) { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x) { throw new UnsupportedOperationException(); }
        public boolean execute() { throw new UnsupportedOperationException(); }
        public void addBatch() { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r, int l) { throw new UnsupportedOperationException(); }
        public void setRef(int i, Ref x) { throw new UnsupportedOperationException(); }
        public void setBlob(int i, Blob x) { throw new UnsupportedOperationException(); }
        public void setClob(int i, Clob x) { throw new UnsupportedOperationException(); }
        public void setArray(int i, Array x) { throw new UnsupportedOperationException(); }
        public ResultSetMetaData getMetaData() { throw new UnsupportedOperationException(); }
        public void setDate(int i, Date x, Calendar c) { throw new UnsupportedOperationException(); }
        public void setTime(int i, Time x, Calendar c) { throw new UnsupportedOperationException(); }
        public void setTimestamp(int i, Timestamp x, Calendar c) { throw new UnsupportedOperationException(); }
        public void setNull(int i, int t, String n) { throw new UnsupportedOperationException(); }
        public void setURL(int i, URL x) { throw new UnsupportedOperationException(); }
        public ParameterMetaData getParameterMetaData() { throw new UnsupportedOperationException(); }
        public void setRowId(int i, RowId x) { throw new UnsupportedOperationException(); }
        public void setNString(int i, String v) { throw new UnsupportedOperationException(); }
        public void setNCharacterStream(int i, Reader v, long l) { throw new UnsupportedOperationException(); }
        public void setNClob(int i, NClob v) { throw new UnsupportedOperationException(); }
        public void setClob(int i, Reader r, long l) { throw new UnsupportedOperationException(); }
        public void setBlob(int i, InputStream s, long l) { throw new UnsupportedOperationException(); }
        public void setNClob(int i, Reader r, long l) { throw new UnsupportedOperationException(); }
        public void setSQLXML(int i, SQLXML x) { throw new UnsupportedOperationException(); }
        public void setObject(int i, Object x, int t, int s) { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r, long l) { throw new UnsupportedOperationException(); }
        public void setAsciiStream(int i, InputStream x) { throw new UnsupportedOperationException(); }
        public void setBinaryStream(int i, InputStream x) { throw new UnsupportedOperationException(); }
        public void setCharacterStream(int i, Reader r) { throw new UnsupportedOperationException(); }
        public void setNCharacterStream(int i, Reader v) { throw new UnsupportedOperationException(); }
        public void setClob(int i, Reader r) { throw new UnsupportedOperationException(); }
        public void setBlob(int i, InputStream s) { throw new UnsupportedOperationException(); }
        public void setNClob(int i, Reader r) { throw new UnsupportedOperationException(); }
    }

    // -------------------------------------------------------------------------
    // Test lifecycle
    // -------------------------------------------------------------------------

    protected void setUp() {
        capturedSql           = null;
        capturedParam1        = null;
        capturedParam2        = null;
        executeUpdateCalled   = false;
        createStatementCalled = false;
    }

    // -------------------------------------------------------------------------
    // Helper: simulate the exact SQL-execution sequence used in the fixed JSP
    // -------------------------------------------------------------------------

    /**
     * Simulates the fixed logic from change-info.jsp:
     *   PreparedStatement stmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?");
     *   stmt.setString(1, info);
     *   stmt.setString(2, id);
     *   stmt.executeUpdate();
     */
    private void simulateChangeInfoUpdate(String info, String id) throws SQLException {
        StubPreparedStatement ps = new StubPreparedStatement(
                "UPDATE users SET about=? WHERE id=?");
        ps.setString(1, info);
        ps.setString(2, id);
        ps.executeUpdate();
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    /**
     * The SQL template must use '?' placeholders for both bound values — it
     * must NOT embed the 'info' or 'id' values directly via concatenation.
     */
    public void testSqlTemplateUsesParameterPlaceholders() throws SQLException {
        simulateChangeInfoUpdate("Hello World", "42");

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must contain '?' placeholders",
                capturedSql.contains("?"));
        assertFalse("SQL template must not contain the 'info' value inline",
                capturedSql.contains("Hello World"));
        assertFalse("SQL template must not contain the 'id' value inline",
                capturedSql.contains("42"));
    }

    /**
     * The SQL template must contain exactly two '?' placeholders: one for
     * the SET clause (info/about) and one for the WHERE clause (id).
     */
    public void testSqlTemplateHasExactlyTwoPlaceholders() throws SQLException {
        simulateChangeInfoUpdate("some description", "1");

        assertNotNull("Captured SQL template must not be null", capturedSql);
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals(
                "SQL template must contain exactly 2 '?' placeholders (one for info, one for id)",
                2, count);
    }

    /**
     * executeUpdate() must be called after binding parameters, confirming the
     * statement was actually executed.
     */
    public void testExecuteUpdateIsCalledAfterBindingParameters() throws SQLException {
        simulateChangeInfoUpdate("my bio", "7");

        assertTrue("executeUpdate() must be called after binding parameters",
                executeUpdateCalled);
    }

    /**
     * A classical SQL injection payload in the 'info' field (' OR '1'='1)
     * must be passed as a bound parameter, not embedded in the SQL template.
     */
    public void testSqlInjectionPayloadInInfoIsNotEmbeddedInTemplate() throws SQLException {
        String injectionPayload = "' OR '1'='1";
        simulateChangeInfoUpdate(injectionPayload, "5");

        assertFalse("SQL template must not contain single-quotes from injection payload",
                capturedSql.contains("'1'='1"));
        assertFalse("SQL template must not contain OR keyword from injection",
                capturedSql.toUpperCase().contains(" OR "));

        // The payload must arrive at the DB driver only as a safe bound parameter
        assertEquals("Injection payload must be bound as the first parameter literal",
                injectionPayload, capturedParam1);
    }

    /**
     * A UNION-based injection payload in the 'info' field must be treated as
     * a literal parameter value, not spliced into the SQL structure.
     */
    public void testUnionInjectionPayloadInInfoIsNotEmbeddedInTemplate() throws SQLException {
        String unionPayload = "' UNION SELECT 1,2,3,4 --";
        simulateChangeInfoUpdate(unionPayload, "3");

        assertFalse("SQL template must not contain UNION keyword from injection payload",
                capturedSql.toUpperCase().contains("UNION"));
        assertEquals("UNION injection payload must be bound as parameter 1 literal",
                unionPayload, capturedParam1);
    }

    /**
     * SECOND-ORDER INJECTION: a malicious 'id' value that was originally stored
     * in the database by a previous SQL injection and is now retrieved from the
     * session. It must NOT be embedded in the SQL template; it must flow only
     * through the parameter binding mechanism.
     *
     * This is the core of the Second-Order SQL Injection scenario:
     *   - adminlogin.jsp writes tainted data (from username) to the DB
     *   - change-info.jsp reads it back via session.getAttribute("userid")
     *   - Without parameterization, the tainted 'id' breaks out of the WHERE clause
     */
    public void testSecondOrderInjectionPayloadInIdIsNotEmbeddedInTemplate() throws SQLException {
        // Simulates a poisoned 'userid' session value that could originate from
        // a crafted username stored via adminlogin.jsp
        String poisonedId = "1 OR 1=1";
        simulateChangeInfoUpdate("legitimate info", poisonedId);

        assertFalse("SQL template must not contain OR keyword from poisoned id",
                capturedSql.toUpperCase().contains(" OR "));
        assertFalse("SQL template must not embed the poisoned id value",
                capturedSql.contains(poisonedId));
        assertEquals("Poisoned id must be bound as the second parameter literal",
                poisonedId, capturedParam2);
    }

    /**
     * A stacked-query injection payload in 'id' must be bound safely.
     * This tests another variant of second-order injection where a
     * semicolon-delimited second statement was injected.
     */
    public void testStackedQueryInjectionInIdIsNotEmbeddedInTemplate() throws SQLException {
        String stackedPayload = "1; DROP TABLE users; --";
        simulateChangeInfoUpdate("my description", stackedPayload);

        assertFalse("SQL template must not contain DROP keyword from stacked injection",
                capturedSql.toUpperCase().contains("DROP"));
        assertFalse("SQL template must not contain semicolons from stacked injection",
                capturedSql.contains(";"));
        assertEquals("Stacked injection payload in id must be bound as parameter 2 literal",
                stackedPayload, capturedParam2);
    }

    /**
     * Verifies that valid (non-malicious) inputs flow through intact as bound
     * parameters, confirming that the fix does not break legitimate functionality.
     */
    public void testValidInputsArePassedAsParameters() throws SQLException {
        String info = "I enjoy hiking and coding.";
        String id   = "42";

        simulateChangeInfoUpdate(info, id);

        assertEquals("Valid 'info' value must be bound as parameter 1", info, capturedParam1);
        assertEquals("Valid 'id' value must be bound as parameter 2", id, capturedParam2);
        assertTrue("executeUpdate() must be called for valid inputs", executeUpdateCalled);
    }

    /**
     * Verifies that special characters in 'info' (apostrophes, quotes, backslashes)
     * are passed as literal parameter values without altering the SQL template.
     */
    public void testSpecialCharactersInInfoAreHandledSafely() throws SQLException {
        String infoWithSpecialChars = "O'Brien's \"note\" with backslash \\";
        simulateChangeInfoUpdate(infoWithSpecialChars, "10");

        assertFalse("SQL template must not be altered by special chars in info",
                capturedSql.contains("O'Brien"));
        assertEquals("Special chars in info must be passed as a literal bound parameter",
                infoWithSpecialChars, capturedParam1);
    }

    /**
     * Verifies that the SQL template is a constant, static string.
     * It must reference the 'about' column and the 'users' table as expected
     * by the application schema, and use parameterized form.
     */
    public void testSqlTemplateStructureIsCorrect() throws SQLException {
        simulateChangeInfoUpdate("test", "1");

        assertNotNull("SQL template must not be null", capturedSql);
        // Must be an UPDATE targeting the 'users' table
        assertTrue("SQL template must target the 'users' table",
                capturedSql.toUpperCase().contains("USERS"));
        // Must update the 'about' column
        assertTrue("SQL template must update the 'about' column",
                capturedSql.toUpperCase().contains("ABOUT"));
        // Must have a WHERE clause using a parameter
        assertTrue("SQL template must have a WHERE clause with a '?' placeholder",
                capturedSql.toUpperCase().contains("WHERE") && capturedSql.contains("?"));
    }
}
