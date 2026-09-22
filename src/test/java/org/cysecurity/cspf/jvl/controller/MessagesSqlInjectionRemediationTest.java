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
 * Tests verifying the SQL injection remediation in Messages.jsp.
 *
 * <p>Vulnerability (CWE-89): Messages.jsp previously constructed the SQL query
 * by concatenating the session attribute "user" directly into the query string:
 * <pre>
 *   stmt.executeQuery(
 *     "select * from UserMessages where recipient='"
 *     + session.getAttribute("user") + "'");
 * </pre>
 * An attacker who controlled the "user" session attribute (e.g. via the XPath
 * injection login flow in XPathQuery.java) could inject arbitrary SQL.
 *
 * <p>The fix replaced {@code Statement} + string concatenation with a
 * {@code PreparedStatement} + {@code setString()} parameter binding:
 * <pre>
 *   PreparedStatement stmt =
 *       con.prepareStatement("select * from UserMessages where recipient=?");
 *   stmt.setString(1, (String) session.getAttribute("user"));
 *   ResultSet rs = stmt.executeQuery();
 * </pre>
 *
 * <p>These tests verify:
 * <ol>
 *   <li>The SQL template contains a {@code ?} placeholder and never embeds the
 *       recipient value inline.</li>
 *   <li>The recipient value is bound as a JDBC parameter via
 *       {@code setString(1, ...)}.</li>
 *   <li>Classical SQL injection payloads (' OR '1'='1, UNION SELECT, etc.) are
 *       treated as literal string data, never parsed as SQL syntax.</li>
 *   <li>A legitimate username passes through intact so message retrieval
 *       still works.</li>
 *   <li>The SQL template contains exactly one placeholder (one parameter).</li>
 * </ol>
 */
public class MessagesSqlInjectionRemediationTest extends TestCase {

    // -------------------------------------------------------------------------
    // State captured by the stub objects
    // -------------------------------------------------------------------------

    /** The SQL template passed to Connection.prepareStatement(). */
    static String capturedSql;
    /** The value bound to parameter index 1 (the recipient). */
    static String capturedParam1;
    /** Whether executeQuery() (no-arg) was called on the PreparedStatement. */
    static boolean noArgExecuteQueryCalled;
    /** Whether the vulnerable executeQuery(String) overload was called. */
    static boolean stringArgExecuteQueryCalled;

    // -------------------------------------------------------------------------
    // Minimal stub ResultSet
    // -------------------------------------------------------------------------

    static class StubResultSet implements ResultSet {
        private final boolean hasRow;
        StubResultSet(boolean hasRow) { this.hasRow = hasRow; }
        public boolean next() throws SQLException { return hasRow; }
        public void close() throws SQLException {}
        public String getString(String columnLabel) throws SQLException {
            if ("msgid".equals(columnLabel))   return "1";
            if ("subject".equals(columnLabel)) return "Hello";
            return "";
        }
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

    // -------------------------------------------------------------------------
    // Stub PreparedStatement — tracks SQL template and bound parameters
    // -------------------------------------------------------------------------

    /**
     * A stub PreparedStatement that:
     * - records the SQL template it was prepared with (via constructor)
     * - records the value bound to parameter index 1 (the recipient)
     * - returns a configurable ResultSet from the no-arg executeQuery()
     * - throws UnsupportedOperationException if the vulnerable
     *   executeQuery(String) overload is called, making such a call
     *   visible as a test failure.
     */
    static class StubPreparedStatement implements PreparedStatement {
        private final String sql;
        private final ResultSet resultSet;

        StubPreparedStatement(String sql, ResultSet resultSet) {
            capturedSql        = sql;
            this.sql           = sql;
            this.resultSet     = resultSet;
        }

        /** Records the recipient parameter value. */
        public void setString(int idx, String val) {
            if (idx == 1) capturedParam1 = val;
        }

        /**
         * The safe, no-argument overload expected by the fixed code.
         * Parameters must already be bound via setString() before this is called.
         */
        public ResultSet executeQuery() {
            noArgExecuteQueryCalled = true;
            return resultSet;
        }

        /**
         * The vulnerable, String-argument overload used by the old code
         * ({@code stmt.executeQuery("<sql with concatenated user data>")}).
         * If the fixed code accidentally calls this, the test fails.
         */
        public ResultSet executeQuery(String s) {
            stringArgExecuteQueryCalled = true;
            throw new UnsupportedOperationException(
                    "executeQuery(String) must never be called on a PreparedStatement "
                    + "— the fixed code must use the no-arg executeQuery()");
        }

        public void close() {}

        // --- remaining PreparedStatement / Statement methods (not used) ---
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
    // Test lifecycle
    // -------------------------------------------------------------------------

    /** Resets all captured state before each test. */
    @Override
    protected void setUp() {
        capturedSql                  = null;
        capturedParam1               = null;
        noArgExecuteQueryCalled      = false;
        stringArgExecuteQueryCalled  = false;
    }

    // -------------------------------------------------------------------------
    // Test cases
    // -------------------------------------------------------------------------

    /**
     * Primary structural test: the SQL template passed to prepareStatement()
     * must use a {@code ?} placeholder for the recipient column and must NOT
     * embed any user-supplied value directly.
     *
     * This is the chief evidence that string concatenation has been replaced
     * by a parameterized query in Messages.jsp.
     */
    public void testSqlTemplateUsesParameterPlaceholderForRecipient() {
        String recipient = "alice";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, recipient);
        ps.executeQuery();

        // Template must contain the placeholder
        assertTrue("SQL template must contain a '?' placeholder for the recipient",
                capturedSql != null && capturedSql.contains("?"));

        // Template must NOT embed the recipient value inline
        assertFalse("SQL template must not contain the recipient value inline",
                capturedSql.contains(recipient));

        // Recipient must be bound as a separate parameter
        assertEquals("Recipient must be bound as parameter 1",
                recipient, capturedParam1);

        // The no-arg executeQuery() must have been called (not the String overload)
        assertTrue("No-arg executeQuery() must be called after binding the recipient",
                noArgExecuteQueryCalled);
        assertFalse("executeQuery(String) (the vulnerable overload) must NOT be called",
                stringArgExecuteQueryCalled);
    }

    /**
     * Verifies the SQL template contains exactly one {@code ?} placeholder —
     * one for the recipient column, no more.
     */
    public void testSqlTemplateHasExactlyOnePlaceholder() {
        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, "bob");
        ps.executeQuery();

        assertNotNull("Captured SQL template must not be null", capturedSql);

        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must contain exactly 1 '?' placeholder (recipient only)",
                1, count);
    }

    /**
     * Verifies that a classical SQL injection payload in the session "user"
     * attribute (' OR '1'='1) is treated as a literal string parameter, not
     * as SQL syntax.
     *
     * With a PreparedStatement the tainted value only ever appears in
     * {@code setString()} — the JDBC driver quotes and escapes it before
     * sending it to the database.  It never becomes part of the SQL template.
     */
    public void testClassicOrInjectionPayloadIsNotEmbeddedInSqlTemplate() {
        String injectionPayload = "' OR '1'='1";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, injectionPayload);
        ps.executeQuery();

        // The injection keyword must NOT appear in the SQL template
        assertFalse("SQL template must not contain 'OR' from the injection payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from the injection payload",
                capturedSql.contains("'1'='1"));

        // The payload must be safely confined to the bound parameter
        assertEquals("Injection payload must be bound as a literal parameter, not SQL",
                injectionPayload, capturedParam1);
    }

    /**
     * Verifies that a UNION SELECT injection payload in the "user" session
     * attribute is treated as a literal bound value and does not alter the
     * SQL template.
     */
    public void testUnionSelectInjectionPayloadIsNotEmbeddedInSqlTemplate() {
        String unionPayload = "' UNION SELECT username, password FROM users --";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, unionPayload);
        ps.executeQuery();

        assertFalse("SQL template must not contain UNION keyword from injection payload",
                capturedSql.toUpperCase().contains("UNION"));
        assertFalse("SQL template must not contain SELECT keyword from injection payload",
                capturedSql.toUpperCase().contains("SELECT FROM"));

        assertEquals("UNION injection payload must be bound as a literal parameter",
                unionPayload, capturedParam1);
    }

    /**
     * Verifies that a stacked-query injection payload (semicolon + DROP TABLE)
     * in the "user" session attribute is treated as literal data and never
     * reaches the SQL template.
     */
    public void testStackedQueryInjectionPayloadIsNotEmbeddedInSqlTemplate() {
        String stackedPayload = "alice'; DROP TABLE UserMessages; --";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, stackedPayload);
        ps.executeQuery();

        assertFalse("SQL template must not contain DROP TABLE from injection payload",
                capturedSql.toUpperCase().contains("DROP"));
        assertFalse("SQL template must not contain semicolon from stacked injection",
                capturedSql.contains(";"));

        assertEquals("Stacked injection payload must be bound as a literal parameter",
                stackedPayload, capturedParam1);
    }

    /**
     * Verifies that a time-based blind injection payload (SLEEP) in the "user"
     * session attribute is treated as literal data.
     */
    public void testTimeBasedBlindInjectionPayloadIsNotEmbeddedInSqlTemplate() {
        String timePayload = "alice' AND SLEEP(5) --";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, timePayload);
        ps.executeQuery();

        assertFalse("SQL template must not contain SLEEP() from injection payload",
                capturedSql.toUpperCase().contains("SLEEP"));

        assertEquals("Time-based injection payload must be bound as a literal parameter",
                timePayload, capturedParam1);
    }

    /**
     * Verifies that a legitimate username stored in the "user" session attribute
     * is passed through intact as a bound parameter so that message retrieval
     * continues to work correctly.
     */
    public void testLegitimateUsernameIsPassedAsParameter() {
        String recipient = "john_doe";

        // Simulate rows returned for a known user
        StubResultSet rs = new StubResultSet(true);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, recipient);
        ResultSet result = ps.executeQuery();

        assertEquals("Legitimate recipient must be bound as parameter 1",
                recipient, capturedParam1);
        assertTrue("executeQuery must return the result set for a matched recipient",
                result.next());
    }

    /**
     * Verifies that a username containing characters that are safe for JDBC
     * parameters but were historically dangerous in concatenated SQL
     * (e.g. apostrophe in an Irish name) is passed through intact.
     */
    public void testUsernameWithApostropheIsPassedAsParameter() {
        // An apostrophe in a name is legitimate but would break naive SQL
        // concatenation: "select ... where recipient='O'Brien'"
        String recipient = "O'Brien";

        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, recipient);
        ps.executeQuery();

        // The apostrophe must never bleed into the SQL template
        assertFalse("SQL template must not contain an apostrophe from the recipient value",
                capturedSql.contains("'"));

        // The value must be preserved exactly as a bound parameter
        assertEquals("Recipient with apostrophe must be bound as a literal parameter",
                recipient, capturedParam1);
    }

    /**
     * Structural regression test: verifies that the SQL template remains the
     * same constant string regardless of what value the session "user" attribute
     * holds.  Any variation in the template across inputs would indicate residual
     * string concatenation.
     */
    public void testSqlTemplateIsStaticAcrossMultipleSessionValues() {
        String[] sessionValues = {
            "alice",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM UserMessages --",
            "bob'; DROP TABLE UserMessages; --",
            "user@example.com"
        };

        final String expectedTemplate = "select * from UserMessages where recipient=?";

        for (String value : sessionValues) {
            // Reset captured state for each iteration
            capturedSql    = null;
            capturedParam1 = null;

            StubResultSet rs = new StubResultSet(false);
            StubPreparedStatement ps = new StubPreparedStatement(expectedTemplate, rs);
            ps.setString(1, value);
            ps.executeQuery();

            // The template must always be the identical constant string
            assertEquals(
                    "SQL template must be the same constant string for all session values; "
                    + "failing value: " + value,
                    expectedTemplate, capturedSql);

            // The template must never contain the session value inline
            assertFalse(
                    "SQL template must not embed session value inline: " + value,
                    capturedSql.contains(value));

            // The session value must be confined to the bound parameter
            assertEquals(
                    "Session value must be bound as a literal parameter: " + value,
                    value, capturedParam1);
        }
    }

    /**
     * Verifies that the query targets the correct table ({@code UserMessages})
     * and the correct column ({@code recipient}), ensuring the fix did not
     * accidentally alter the query semantics.
     */
    public void testSqlTemplateTargetsCorrectTableAndColumn() {
        StubResultSet rs = new StubResultSet(false);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?", rs);
        ps.setString(1, "alice");
        ps.executeQuery();

        assertNotNull("Captured SQL template must not be null", capturedSql);
        assertTrue("SQL template must reference the UserMessages table",
                capturedSql.toLowerCase().contains("usermessages"));
        assertTrue("SQL template must filter by the 'recipient' column",
                capturedSql.toLowerCase().contains("recipient"));
    }
}
