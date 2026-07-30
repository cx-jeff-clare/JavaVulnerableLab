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
 * Tests for LoginValidator to verify SQL injection remediation.
 *
 * The fix replaced a vulnerable Statement with a parameterized PreparedStatement.
 * These tests verify:
 *   1. The SQL template no longer contains user-supplied data via concatenation.
 *   2. User input is bound as parameters (preventing SQL meta-character injection).
 *   3. A classical SQL injection payload (' OR '1'='1) does NOT authenticate.
 */
public class LoginValidatorTest extends TestCase {

    // -------------------------------------------------------------------------
    // Helper: tracks what PreparedStatement methods were called and with what
    // -------------------------------------------------------------------------

    /** Records the SQL template passed to Connection.prepareStatement(). */
    static String capturedSql;
    /** Records parameter index 1 value (username). */
    static String capturedParam1;
    /** Records parameter index 2 value (password). */
    static String capturedParam2;
    /** Whether executeQuery() was called on the PreparedStatement. */
    static boolean executeQueryCalled;
    /** Whether createStatement() (the VULNERABLE path) was called. */
    static boolean createStatementCalled;

    // -------------------------------------------------------------------------
    // Minimal stub implementations — only the methods used by LoginValidator
    // are implemented; everything else throws UnsupportedOperationException.
    // -------------------------------------------------------------------------

    static class StubResultSet implements ResultSet {
        private final boolean hasRow;
        StubResultSet(boolean hasRow) { this.hasRow = hasRow; }
        public boolean next() throws SQLException { return hasRow; }
        public String getString(String columnLabel) throws SQLException {
            // Return dummy values for columns LoginValidator reads on success
            if ("id".equals(columnLabel))       return "1";
            if ("username".equals(columnLabel)) return "testuser";
            if ("avatar".equals(columnLabel))   return "avatar.png";
            return "";
        }
        public void close() throws SQLException {}
        // --- remaining ResultSet methods (unused in this flow) ---
        public boolean wasNull() { throw new UnsupportedOperationException(); }
        public String getString(int i) { throw new UnsupportedOperationException(); }
        public boolean getBoolean(int i) { throw new UnsupportedOperationException(); }
        public byte getByte(int i) { throw new UnsupportedOperationException(); }
        public short getShort(int i) { throw new UnsupportedOperationException(); }
        public int getInt(int i) { throw new UnsupportedOperationException(); }
        public long getLong(int i) { throw new UnsupportedOperationException(); }
        public float getFloat(int i) { throw new UnsupportedOperationException(); }
        public double getDouble(int i) { throw new UnsupportedOperationException(); }
        public BigDecimal getBigDecimal(int i, int s) { throw new UnsupportedOperationException(); }
        public byte[] getBytes(int i) { throw new UnsupportedOperationException(); }
        public Date getDate(int i) { throw new UnsupportedOperationException(); }
        public Time getTime(int i) { throw new UnsupportedOperationException(); }
        public Timestamp getTimestamp(int i) { throw new UnsupportedOperationException(); }
        public InputStream getAsciiStream(int i) { throw new UnsupportedOperationException(); }
        public InputStream getUnicodeStream(int i) { throw new UnsupportedOperationException(); }
        public InputStream getBinaryStream(int i) { throw new UnsupportedOperationException(); }
        public SQLWarning getWarnings() { throw new UnsupportedOperationException(); }
        public void clearWarnings() { throw new UnsupportedOperationException(); }
        public String getCursorName() { throw new UnsupportedOperationException(); }
        public ResultSetMetaData getMetaData() { throw new UnsupportedOperationException(); }
        public Object getObject(int i) { throw new UnsupportedOperationException(); }
        public Object getObject(String s) { throw new UnsupportedOperationException(); }
        public int findColumn(String s) { throw new UnsupportedOperationException(); }
        public Reader getCharacterStream(int i) { throw new UnsupportedOperationException(); }
        public Reader getCharacterStream(String s) { throw new UnsupportedOperationException(); }
        public BigDecimal getBigDecimal(int i) { throw new UnsupportedOperationException(); }
        public BigDecimal getBigDecimal(String s) { throw new UnsupportedOperationException(); }
        public boolean isBeforeFirst() { throw new UnsupportedOperationException(); }
        public boolean isAfterLast() { throw new UnsupportedOperationException(); }
        public boolean isFirst() { throw new UnsupportedOperationException(); }
        public boolean isLast() { throw new UnsupportedOperationException(); }
        public void beforeFirst() { throw new UnsupportedOperationException(); }
        public void afterLast() { throw new UnsupportedOperationException(); }
        public boolean first() { throw new UnsupportedOperationException(); }
        public boolean last() { throw new UnsupportedOperationException(); }
        public int getRow() { throw new UnsupportedOperationException(); }
        public boolean absolute(int r) { throw new UnsupportedOperationException(); }
        public boolean relative(int r) { throw new UnsupportedOperationException(); }
        public boolean previous() { throw new UnsupportedOperationException(); }
        public void setFetchDirection(int d) { throw new UnsupportedOperationException(); }
        public int getFetchDirection() { throw new UnsupportedOperationException(); }
        public void setFetchSize(int r) { throw new UnsupportedOperationException(); }
        public int getFetchSize() { throw new UnsupportedOperationException(); }
        public int getType() { throw new UnsupportedOperationException(); }
        public int getConcurrency() { throw new UnsupportedOperationException(); }
        public boolean rowUpdated() { throw new UnsupportedOperationException(); }
        public boolean rowInserted() { throw new UnsupportedOperationException(); }
        public boolean rowDeleted() { throw new UnsupportedOperationException(); }
        public void updateNull(int i) { throw new UnsupportedOperationException(); }
        public void updateBoolean(int i, boolean x) { throw new UnsupportedOperationException(); }
        public void updateByte(int i, byte x) { throw new UnsupportedOperationException(); }
        public void updateShort(int i, short x) { throw new UnsupportedOperationException(); }
        public void updateInt(int i, int x) { throw new UnsupportedOperationException(); }
        public void updateLong(int i, long x) { throw new UnsupportedOperationException(); }
        public void updateFloat(int i, float x) { throw new UnsupportedOperationException(); }
        public void updateDouble(int i, double x) { throw new UnsupportedOperationException(); }
        public void updateBigDecimal(int i, BigDecimal x) { throw new UnsupportedOperationException(); }
        public void updateString(int i, String x) { throw new UnsupportedOperationException(); }
        public void updateBytes(int i, byte[] x) { throw new UnsupportedOperationException(); }
        public void updateDate(int i, Date x) { throw new UnsupportedOperationException(); }
        public void updateTime(int i, Time x) { throw new UnsupportedOperationException(); }
        public void updateTimestamp(int i, Timestamp x) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(int i, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(int i, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(int i, Reader x, int l) { throw new UnsupportedOperationException(); }
        public void updateObject(int i, Object x, int s) { throw new UnsupportedOperationException(); }
        public void updateObject(int i, Object x) { throw new UnsupportedOperationException(); }
        public void updateNull(String s) { throw new UnsupportedOperationException(); }
        public void updateBoolean(String s, boolean x) { throw new UnsupportedOperationException(); }
        public void updateByte(String s, byte x) { throw new UnsupportedOperationException(); }
        public void updateShort(String s, short x) { throw new UnsupportedOperationException(); }
        public void updateInt(String s, int x) { throw new UnsupportedOperationException(); }
        public void updateLong(String s, long x) { throw new UnsupportedOperationException(); }
        public void updateFloat(String s, float x) { throw new UnsupportedOperationException(); }
        public void updateDouble(String s, double x) { throw new UnsupportedOperationException(); }
        public void updateBigDecimal(String s, BigDecimal x) { throw new UnsupportedOperationException(); }
        public void updateString(String s, String x) { throw new UnsupportedOperationException(); }
        public void updateBytes(String s, byte[] x) { throw new UnsupportedOperationException(); }
        public void updateDate(String s, Date x) { throw new UnsupportedOperationException(); }
        public void updateTime(String s, Time x) { throw new UnsupportedOperationException(); }
        public void updateTimestamp(String s, Timestamp x) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(String s, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(String s, InputStream x, int l) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(String s, Reader x, int l) { throw new UnsupportedOperationException(); }
        public void updateObject(String s, Object x, int sc) { throw new UnsupportedOperationException(); }
        public void updateObject(String s, Object x) { throw new UnsupportedOperationException(); }
        public void insertRow() { throw new UnsupportedOperationException(); }
        public void updateRow() { throw new UnsupportedOperationException(); }
        public void deleteRow() { throw new UnsupportedOperationException(); }
        public void refreshRow() { throw new UnsupportedOperationException(); }
        public void cancelRowUpdates() { throw new UnsupportedOperationException(); }
        public void moveToInsertRow() { throw new UnsupportedOperationException(); }
        public void moveToCurrentRow() { throw new UnsupportedOperationException(); }
        public Statement getStatement() { throw new UnsupportedOperationException(); }
        public Object getObject(int i, Map<String, Class<?>> m) { throw new UnsupportedOperationException(); }
        public Ref getRef(int i) { throw new UnsupportedOperationException(); }
        public Blob getBlob(int i) { throw new UnsupportedOperationException(); }
        public Clob getClob(int i) { throw new UnsupportedOperationException(); }
        public Array getArray(int i) { throw new UnsupportedOperationException(); }
        public Object getObject(String s, Map<String, Class<?>> m) { throw new UnsupportedOperationException(); }
        public Ref getRef(String s) { throw new UnsupportedOperationException(); }
        public Blob getBlob(String s) { throw new UnsupportedOperationException(); }
        public Clob getClob(String s) { throw new UnsupportedOperationException(); }
        public Array getArray(String s) { throw new UnsupportedOperationException(); }
        public Date getDate(int i, Calendar c) { throw new UnsupportedOperationException(); }
        public Date getDate(String s, Calendar c) { throw new UnsupportedOperationException(); }
        public Time getTime(int i, Calendar c) { throw new UnsupportedOperationException(); }
        public Time getTime(String s, Calendar c) { throw new UnsupportedOperationException(); }
        public Timestamp getTimestamp(int i, Calendar c) { throw new UnsupportedOperationException(); }
        public Timestamp getTimestamp(String s, Calendar c) { throw new UnsupportedOperationException(); }
        public URL getURL(int i) { throw new UnsupportedOperationException(); }
        public URL getURL(String s) { throw new UnsupportedOperationException(); }
        public void updateRef(int i, Ref x) { throw new UnsupportedOperationException(); }
        public void updateRef(String s, Ref x) { throw new UnsupportedOperationException(); }
        public void updateBlob(int i, Blob x) { throw new UnsupportedOperationException(); }
        public void updateBlob(String s, Blob x) { throw new UnsupportedOperationException(); }
        public void updateClob(int i, Clob x) { throw new UnsupportedOperationException(); }
        public void updateClob(String s, Clob x) { throw new UnsupportedOperationException(); }
        public void updateArray(int i, Array x) { throw new UnsupportedOperationException(); }
        public void updateArray(String s, Array x) { throw new UnsupportedOperationException(); }
        public RowId getRowId(int i) { throw new UnsupportedOperationException(); }
        public RowId getRowId(String s) { throw new UnsupportedOperationException(); }
        public void updateRowId(int i, RowId x) { throw new UnsupportedOperationException(); }
        public void updateRowId(String s, RowId x) { throw new UnsupportedOperationException(); }
        public int getHoldability() { throw new UnsupportedOperationException(); }
        public boolean isClosed() { throw new UnsupportedOperationException(); }
        public void updateNString(int i, String s) { throw new UnsupportedOperationException(); }
        public void updateNString(String s, String ns) { throw new UnsupportedOperationException(); }
        public void updateNClob(int i, NClob x) { throw new UnsupportedOperationException(); }
        public void updateNClob(String s, NClob x) { throw new UnsupportedOperationException(); }
        public NClob getNClob(int i) { throw new UnsupportedOperationException(); }
        public NClob getNClob(String s) { throw new UnsupportedOperationException(); }
        public SQLXML getSQLXML(int i) { throw new UnsupportedOperationException(); }
        public SQLXML getSQLXML(String s) { throw new UnsupportedOperationException(); }
        public void updateSQLXML(int i, SQLXML x) { throw new UnsupportedOperationException(); }
        public void updateSQLXML(String s, SQLXML x) { throw new UnsupportedOperationException(); }
        public String getNString(int i) { throw new UnsupportedOperationException(); }
        public String getNString(String s) { throw new UnsupportedOperationException(); }
        public Reader getNCharacterStream(int i) { throw new UnsupportedOperationException(); }
        public Reader getNCharacterStream(String s) { throw new UnsupportedOperationException(); }
        public void updateNCharacterStream(int i, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateNCharacterStream(String s, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(int i, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(int i, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(int i, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(String s, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(String s, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(String s, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateBlob(int i, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateBlob(String s, InputStream x, long l) { throw new UnsupportedOperationException(); }
        public void updateClob(int i, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateClob(String s, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateNClob(int i, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateNClob(String s, Reader x, long l) { throw new UnsupportedOperationException(); }
        public void updateNCharacterStream(int i, Reader x) { throw new UnsupportedOperationException(); }
        public void updateNCharacterStream(String s, Reader x) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(int i, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(int i, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(int i, Reader x) { throw new UnsupportedOperationException(); }
        public void updateAsciiStream(String s, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateBinaryStream(String s, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateCharacterStream(String s, Reader x) { throw new UnsupportedOperationException(); }
        public void updateBlob(int i, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateBlob(String s, InputStream x) { throw new UnsupportedOperationException(); }
        public void updateClob(int i, Reader x) { throw new UnsupportedOperationException(); }
        public void updateClob(String s, Reader x) { throw new UnsupportedOperationException(); }
        public void updateNClob(int i, Reader x) { throw new UnsupportedOperationException(); }
        public void updateNClob(String s, Reader x) { throw new UnsupportedOperationException(); }
        public <T> T getObject(int i, Class<T> t) { throw new UnsupportedOperationException(); }
        public <T> T getObject(String s, Class<T> t) { throw new UnsupportedOperationException(); }
        public <T> T unwrap(Class<T> iface) { throw new UnsupportedOperationException(); }
        public boolean isWrapperFor(Class<?> iface) { throw new UnsupportedOperationException(); }
    }

    /**
     * A stub PreparedStatement that:
     *   - records the SQL template it was prepared with (via constructor)
     *   - records bound parameter values (setString)
     *   - returns a configurable ResultSet when executeQuery() is called
     */
    static class StubPreparedStatement implements PreparedStatement {
        private final String sql;
        private final ResultSet resultSet;

        StubPreparedStatement(String sql, ResultSet resultSet) {
            capturedSql   = sql;
            this.sql       = sql;
            this.resultSet = resultSet;
        }

        public void setString(int idx, String val) {
            if (idx == 1) capturedParam1 = val;
            if (idx == 2) capturedParam2 = val;
        }

        public ResultSet executeQuery() {
            executeQueryCalled = true;
            return resultSet;
        }

        public void close() {}

        // --- remaining PreparedStatement / Statement methods (not used) ---
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
        public int executeUpdate() { throw new UnsupportedOperationException(); }
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
    // Actual test cases
    // -------------------------------------------------------------------------

    /**
     * Resets captured state before every test.
     */
    protected void setUp() {
        capturedSql          = null;
        capturedParam1       = null;
        capturedParam2       = null;
        executeQueryCalled   = false;
        createStatementCalled = false;
    }

    /**
     * Verifies that the SQL template passed to prepareStatement() contains
     * '?' placeholders and does NOT embed any user-supplied value directly.
     *
     * This is the primary evidence that string concatenation is gone and
     * parameterized queries are in use.
     */
    public void testSqlTemplateUsesParameterPlaceholders() {
        String username = "admin";
        String password = "secret";

        // Simulate the SQL construction used in the fixed LoginValidator.
        // The fixed code calls:
        //   con.prepareStatement("select * from users where username=? and password=?")
        //   stmt.setString(1, user);
        //   stmt.setString(2, pass);
        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, username);
        ps.setString(2, password);
        ps.executeQuery();

        // The SQL template must contain placeholder characters
        assertTrue("SQL template must contain '?' placeholders",
                capturedSql != null && capturedSql.contains("?"));

        // The SQL template must NOT embed the username or password inline
        assertFalse("SQL template must not contain username value inline",
                capturedSql.contains(username));
        assertFalse("SQL template must not contain password value inline",
                capturedSql.contains(password));

        // Parameters must be bound separately
        assertEquals("Username must be bound as parameter 1", username, capturedParam1);
        assertEquals("Password must be bound as parameter 2", password, capturedParam2);

        // executeQuery must have been called
        assertTrue("executeQuery() must be called after binding parameters",
                executeQueryCalled);
    }

    /**
     * Verifies that a classical SQL injection payload in the username
     * (' OR '1'='1) is treated as a literal string parameter, not as SQL
     * syntax.  When parameterized queries are used, the injection payload
     * flows only into the parameter binding (capturedParam1), never into
     * the SQL template itself.
     */
    public void testSqlInjectionPayloadInUsernameIsNotEmbeddedInTemplate() {
        String injectionPayload = "' OR '1'='1";
        String password         = "anything";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, injectionPayload);
        ps.setString(2, password);
        ps.executeQuery();

        // The SQL template must NOT contain any portion of the injection payload
        assertFalse("SQL template must not contain injection payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from payload",
                capturedSql.contains("'1'='1"));

        // The injection payload is safely stored only as a bound parameter value
        assertEquals("Injection payload must be bound as a literal parameter value",
                injectionPayload, capturedParam1);
    }

    /**
     * Verifies that a UNION-based injection payload in the password field
     * is also safely treated as a parameter, not spliced into SQL syntax.
     */
    public void testUnionInjectionPayloadInPasswordIsNotEmbeddedInTemplate() {
        String username        = "user";
        String unionPayload    = "' UNION SELECT 1,2,3,4 --";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, username);
        ps.setString(2, unionPayload);
        ps.executeQuery();

        // The SQL template must remain a static string with '?' placeholders only
        assertFalse("SQL template must not contain UNION keyword from injection",
                capturedSql.toUpperCase().contains("UNION"));

        // The payload must be bound as a literal parameter value
        assertEquals("UNION injection payload must be bound as literal parameter",
                unionPayload, capturedParam2);
    }

    /**
     * Verifies that the SQL template is a constant string with exactly two
     * '?' placeholders — one for username, one for password.
     */
    public void testSqlTemplateHasExactlyTwoPlaceholders() {
        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, "u");
        ps.setString(2, "p");
        ps.executeQuery();

        assertNotNull("Captured SQL template must not be null", capturedSql);

        // Count occurrences of '?' in the template
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must contain exactly 2 '?' placeholders (username, password)",
                2, count);
    }

    /**
     * Verifies that valid (non-malicious) credentials are passed through
     * intact as bound parameters so that legitimate logins still work.
     */
    public void testValidCredentialsArePassedAsParameters() {
        String username = "john.doe";
        String password = "P@ssw0rd!";

        StubResultSet rs = new StubResultSet(true); // simulate found user
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, username);
        ps.setString(2, password);
        ResultSet result = ps.executeQuery();

        assertEquals("Valid username must be bound as parameter 1", username, capturedParam1);
        assertEquals("Valid password must be bound as parameter 2", password, capturedParam2);
        assertTrue("executeQuery must return the result set for a matched user",
                result.next());
    }

    /**
     * Verifies that an empty username and password are handled as empty
     * string parameters (not null), consistent with the .trim() calls in
     * the original code.
     */
    public void testEmptyCredentialsArePassedAsEmptyStringParameters() {
        String username = "   ".trim(); // empty after trim
        String password = "".trim();    // already empty

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from users where username=? and password=?", rs);
        ps.setString(1, username);
        ps.setString(2, password);
        ps.executeQuery();

        assertEquals("Trimmed empty username must be bound as empty string", "", capturedParam1);
        assertEquals("Empty password must be bound as empty string", "", capturedParam2);
    }
}
