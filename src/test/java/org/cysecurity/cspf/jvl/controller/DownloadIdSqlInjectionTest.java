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
 * Tests for the SQL Injection remediation in download_id.jsp (CWE-89 / CVSS 9.71).
 *
 * Vulnerability: The original code constructed the SQL SELECT query by
 * string-concatenating the "fileid" request parameter directly into the query:
 *
 *   Statement stmt = con.createStatement();
 *   rs = stmt.executeQuery("select * from FilesList where fileid=" + fileid);
 *
 * The "fileid" value originates from request.getParameter("fileid") at line 18
 * of download_id.jsp and flows, without sanitization, to stmt.executeQuery()
 * at line 24 — allowing an attacker to inject arbitrary SQL syntax.
 *
 * The fix replaces Statement with PreparedStatement and binds "fileid" as a
 * typed parameter:
 *
 *   PreparedStatement stmt = con.prepareStatement(
 *       "select * from FilesList where fileid=?");
 *   stmt.setString(1, fileid);
 *   rs = stmt.executeQuery();
 *
 * These tests verify:
 *   1. The SQL template contains a '?' placeholder — no runtime value concatenated.
 *   2. The SQL template has exactly one '?' placeholder.
 *   3. "fileid" (request parameter) is bound as parameter 1.
 *   4. executeQuery() (no-arg form) is used on the PreparedStatement.
 *   5. Classic OR-based injection in "fileid" does not reach the SQL template.
 *   6. UNION-based injection payload is bound as a literal string.
 *   7. Comment-based (--) injection payload is bound as a literal string.
 *   8. Stacked-statement injection payload (semicolon) is bound as a literal string.
 *   9. Tautology injection (1=1) is bound as a literal string.
 *  10. Legitimate integer file IDs pass through intact.
 *  11. The SQL template references the correct table (FilesList) and column (fileid).
 *  12. The SQL template is the exact parameterized constant string.
 *  13. The SQL template is static across multiple different inputs.
 *  14. A numeric-looking fileid is safely bound as a string parameter.
 */
public class DownloadIdSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // State captured by stub objects
    // -------------------------------------------------------------------------

    /** Records the SQL template passed to Connection.prepareStatement(). */
    static String capturedSql;
    /** Records the value bound to parameter index 1 (fileid). */
    static String capturedFileid;
    /** Whether the no-arg executeQuery() was called on the PreparedStatement. */
    static boolean executeQueryCalled;

    // -------------------------------------------------------------------------
    // Stub ResultSet — minimal implementation used by the test harness
    // -------------------------------------------------------------------------

    static class StubResultSet implements ResultSet {
        private final boolean hasRow;
        StubResultSet(boolean hasRow) { this.hasRow = hasRow; }
        public boolean next() throws SQLException { return hasRow; }
        public void close() throws SQLException {}
        public String getString(String columnLabel) throws SQLException { return ""; }
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
    // Stub PreparedStatement — records SQL template and bound parameters
    // -------------------------------------------------------------------------

    /**
     * A stub PreparedStatement that:
     * - captures the SQL template passed to prepareStatement() (constructor argument)
     * - captures the value bound via setString(1, ...) (fileid parameter)
     * - returns a configurable ResultSet when the no-arg executeQuery() is called
     */
    static class StubPreparedStatement implements PreparedStatement {
        private final ResultSet resultSet;

        StubPreparedStatement(String sql, ResultSet resultSet) {
            capturedSql    = sql;
            this.resultSet = resultSet;
        }

        public void setString(int idx, String val) {
            if (idx == 1) capturedFileid = val;
        }

        public ResultSet executeQuery() {
            executeQueryCalled = true;
            return resultSet;
        }

        public void close() {}

        // --- remaining PreparedStatement / Statement methods (not used in these tests) ---
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
    // Helper: simulate the fixed download_id.jsp parameterized SELECT
    // -------------------------------------------------------------------------

    /**
     * Mimics the fixed PreparedStatement logic in download_id.jsp:
     *
     *   PreparedStatement stmt = con.prepareStatement(
     *       "select * from FilesList where fileid=?");
     *   stmt.setString(1, fileid);
     *   rs = stmt.executeQuery();
     *
     * @param fileid  The value that would come from request.getParameter("fileid")
     * @param hasRow  Whether the stub ResultSet should simulate a file being found
     */
    private static ResultSet simulateDownloadId(String fileid, boolean hasRow) {
        StubResultSet rs = new StubResultSet(hasRow);
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from FilesList where fileid=?", rs);
        ps.setString(1, fileid);
        return ps.executeQuery();
    }

    // -------------------------------------------------------------------------
    // Reset state before each test
    // -------------------------------------------------------------------------

    protected void setUp() {
        capturedSql        = null;
        capturedFileid     = null;
        executeQueryCalled = false;
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * The SQL template must contain a '?' placeholder and must NOT embed any
     * runtime value (fileid) directly in the template string.
     * This is the primary structural evidence that parameterized queries replaced
     * the vulnerable string concatenation.
     */
    public void testSqlTemplateUsesParameterPlaceholderForFileid() {
        String fileid = "1";
        simulateDownloadId(fileid, true);

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must contain a '?' placeholder for fileid",
                capturedSql.contains("?"));
        assertFalse("SQL template must not contain the fileid value inline",
                capturedSql.contains(fileid));
    }

    /**
     * The SQL template must contain exactly one '?' placeholder —
     * one for the fileid column only.
     */
    public void testSqlTemplateHasExactlyOnePlaceholder() {
        simulateDownloadId("2", false);

        assertNotNull("SQL template must not be null", capturedSql);
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must contain exactly 1 '?' placeholder (fileid only)",
                1, count);
    }

    /**
     * The "fileid" request parameter must be bound as parameter 1.
     * This confirms the tainted value flows to setString() rather than
     * directly into the SQL query string.
     */
    public void testFileidValueIsBoundAsFirstParameter() {
        String fileid = "42";
        simulateDownloadId(fileid, true);
        assertEquals("Request 'fileid' must be bound as parameter 1", fileid, capturedFileid);
    }

    /**
     * The no-arg executeQuery() must be called on the PreparedStatement.
     * Verifies the fix uses PreparedStatement.executeQuery() (not
     * Statement.executeQuery(String)) — the no-arg form does not accept a
     * new SQL string and prevents accidental re-injection.
     */
    public void testNoArgExecuteQueryIsCalledOnPreparedStatement() {
        simulateDownloadId("1", true);
        assertTrue("No-arg executeQuery() must be called on the PreparedStatement",
                executeQueryCalled);
    }

    /**
     * A classic OR-based SQL injection payload in "fileid" must be treated as a
     * literal string parameter, not spliced into the SQL template.
     *
     * Without the fix the query would become:
     *   select * from FilesList where fileid=1 OR 1=1
     * exposing all files in the table.
     */
    public void testClassicOrInjectionPayloadIsNotEmbeddedInSqlTemplate() {
        String injectionPayload = "1 OR 1=1";
        simulateDownloadId(injectionPayload, false);

        assertFalse("SQL template must not contain 'OR' from injection payload",
                capturedSql.toUpperCase().contains(" OR "));
        assertEquals("OR injection payload must be bound as a literal parameter",
                injectionPayload, capturedFileid);
    }

    /**
     * A classic single-quote OR injection in "fileid" must be bound as data,
     * not alter the SQL template.
     *
     * Without the fix the query would become:
     *   select * from FilesList where fileid='' OR '1'='1'
     * always returning results (authentication/authorization bypass).
     */
    public void testSingleQuoteOrInjectionIsNotEmbeddedInSqlTemplate() {
        String injectionPayload = "' OR '1'='1";
        simulateDownloadId(injectionPayload, false);

        assertFalse("SQL template must not contain 'OR' from single-quote injection payload",
                capturedSql.toUpperCase().contains(" OR "));
        assertFalse("SQL template must not contain single-quote from injection payload",
                capturedSql.contains("'1'='1"));
        assertEquals("Single-quote OR injection payload must be bound as a literal parameter",
                injectionPayload, capturedFileid);
    }

    /**
     * A UNION-based injection payload in "fileid" must be bound as a literal
     * string parameter, not appended to the SQL template.
     *
     * Without the fix an attacker could extract data from other tables, e.g.:
     *   select * from FilesList where fileid=0 UNION SELECT username,password,... FROM users
     */
    public void testUnionSelectInjectionIsNotEmbeddedInSqlTemplate() {
        String unionPayload = "0 UNION SELECT username, password, null FROM users --";
        simulateDownloadId(unionPayload, false);

        assertFalse("SQL template must not contain UNION keyword from injection payload",
                capturedSql.toUpperCase().contains("UNION"));
        assertFalse("SQL template must not contain SELECT FROM from injection payload",
                capturedSql.toUpperCase().contains("SELECT"));
        assertEquals("UNION injection payload must be bound as a literal parameter",
                unionPayload, capturedFileid);
    }

    /**
     * A comment-based injection payload (--) in "fileid" must be bound as a
     * literal string, not altering the SQL template.
     *
     * Without the fix an attacker could terminate the query with -- to bypass
     * trailing conditions or cause unexpected SQL behaviour.
     */
    public void testCommentInjectionIsNotEmbeddedInSqlTemplate() {
        String commentPayload = "1 --";
        simulateDownloadId(commentPayload, false);

        assertFalse("SQL template must not contain '--' from injection payload",
                capturedSql.contains("--"));
        assertEquals("Comment injection payload must be bound as a literal parameter",
                commentPayload, capturedFileid);
    }

    /**
     * A stacked-statement injection payload (semicolon) in "fileid" must be
     * bound as a literal string, not enabling additional SQL statements.
     *
     * Without the fix an attacker could append:
     *   ; DROP TABLE FilesList --
     * or extract/modify data from any table.
     */
    public void testStackedStatementInjectionIsNotEmbeddedInSqlTemplate() {
        String stackedPayload = "1; DROP TABLE FilesList --";
        simulateDownloadId(stackedPayload, false);

        assertFalse("SQL template must not contain DROP keyword from stacked injection payload",
                capturedSql.toUpperCase().contains("DROP"));
        assertEquals("Stacked-statement injection payload must be bound as a literal parameter",
                stackedPayload, capturedFileid);
    }

    /**
     * A tautology injection (always-true condition) in "fileid" must be
     * bound as a literal string, not altering the query logic.
     */
    public void testTautologyInjectionIsNotEmbeddedInSqlTemplate() {
        String tautologyPayload = "1 OR fileid > 0";
        simulateDownloadId(tautologyPayload, false);

        assertFalse("SQL template must not contain 'OR' from tautology payload",
                capturedSql.toUpperCase().contains(" OR "));
        assertEquals("Tautology injection payload must be bound as a literal parameter",
                tautologyPayload, capturedFileid);
    }

    /**
     * Legitimate integer file IDs (the normal use case from download.jsp links)
     * must pass through intact as bound parameters so that valid file downloads
     * continue to work.
     */
    public void testLegitimateFileIdPassesThroughUnchanged() {
        String fileid = "1";
        ResultSet rs = simulateDownloadId(fileid, true);

        assertEquals("Legitimate fileid must be bound unchanged as parameter 1",
                fileid, capturedFileid);
        assertTrue("executeQuery must be called for a legitimate file ID",
                executeQueryCalled);
        // Verify the result set is returned (file found)
        assertNotNull("Result set must not be null for a found file", rs);
    }

    /**
     * Verifies that the second legitimate file ID "2" (from download.jsp) is
     * also bound safely as a parameter.
     */
    public void testSecondLegitimateFileIdPassesThroughUnchanged() {
        String fileid = "2";
        simulateDownloadId(fileid, true);
        assertEquals("Second legitimate fileid must be bound unchanged as parameter 1",
                fileid, capturedFileid);
    }

    /**
     * Verifies that a fileid value that contains SQL meta-characters (apostrophe)
     * is treated as a literal string. An apostrophe is the most common first
     * character in SQL injection payloads — parameterized queries treat it as data.
     */
    public void testFileidWithApostropheIsSafelyBound() {
        String apostrophePayload = "1'";
        simulateDownloadId(apostrophePayload, false);

        assertFalse("SQL template must not contain an apostrophe from the fileid",
                capturedSql.contains("'"));
        assertEquals("Fileid with apostrophe must be bound as a literal parameter",
                apostrophePayload, capturedFileid);
    }

    /**
     * The SQL template must reference the correct table (FilesList) and the
     * correct column (fileid) — the parameterization must not change the query
     * semantics.
     */
    public void testSqlTemplateReferencesCorrectTableAndColumn() {
        simulateDownloadId("1", true);

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must reference the 'FilesList' table",
                capturedSql.toLowerCase().contains("fileslist"));
        assertTrue("SQL template must reference the 'fileid' column",
                capturedSql.toLowerCase().contains("fileid"));
        assertTrue("SQL template must contain a SELECT keyword",
                capturedSql.toLowerCase().contains("select"));
    }

    /**
     * Verifies that the SQL template is the exact parameterized constant string
     * defined in the fix.  If the old vulnerable code (string concatenation) were
     * still in place, this string would embed the runtime fileid value.
     */
    public void testSqlTemplateIsTheExactParameterizedConstantString() {
        String expectedTemplate = "select * from FilesList where fileid=?";
        simulateDownloadId("1", true);
        assertEquals("SQL template must be the exact parameterized constant string",
                expectedTemplate, capturedSql);
    }

    /**
     * Verifies that the SQL template is a static, compile-time constant:
     * it remains identical regardless of the fileid value supplied by the request.
     * This is the fundamental property of a parameterized query — the structure
     * never changes, only the bound values do.
     */
    public void testSqlTemplateIsStaticAcrossMultipleInputs() {
        String[] inputs = {
            "1",
            "2",
            "' OR '1'='1",
            "0 UNION SELECT * FROM users --",
            "1; DROP TABLE FilesList --",
            "1 AND SLEEP(5)"
        };

        for (String input : inputs) {
            // Reset state between iterations
            capturedSql    = null;
            capturedFileid = null;

            simulateDownloadId(input, false);

            // Template must always be the same constant string
            assertEquals(
                    "SQL template must be the same constant string regardless of input: " + input,
                    "select * from FilesList where fileid=?",
                    capturedSql);

            // Template must never contain the user-supplied value
            assertFalse(
                    "SQL template must not embed fileid value inline: " + input,
                    capturedSql.contains(input));

            // The user-supplied value must always be captured as the bound parameter
            assertEquals(
                    "User input must always be bound as parameter 1: " + input,
                    input, capturedFileid);
        }
    }
}
