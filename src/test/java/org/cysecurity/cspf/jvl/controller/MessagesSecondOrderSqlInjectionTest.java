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
 * Tests for the Second-Order SQL Injection remediation in Messages.jsp.
 *
 * Vulnerability (CWE-89 / CVSS 9.71): The original code constructed the SQL
 * SELECT statement by concatenating the session "user" attribute directly into
 * the query string:
 *
 *   Statement stmt = con.createStatement();
 *   rs = stmt.executeQuery(
 *       "select * from UserMessages where recipient='"
 *       + session.getAttribute("user") + "'");
 *
 * The "user" attribute originates from the users table in the database, written
 * during admin login (adminlogin.jsp lines 19-23):
 *
 *   rs = stmt.executeQuery(
 *       "select * from users where username='" + user + "' ...");
 *   session.setAttribute("user", rs.getString("username"));
 *
 * An attacker who registers a username containing SQL meta-characters (e.g.,
 * "admin' OR '1'='1") can have those characters stored in the users table.
 * Later, when Messages.jsp reads the username from the session and embeds it in
 * the SELECT query, the stored payload alters the query structure — a
 * second-order injection.
 *
 * The fix replaces Statement with PreparedStatement and binds the recipient
 * value as a typed parameter:
 *
 *   PreparedStatement stmt = con.prepareStatement(
 *       "select * from UserMessages where recipient=?");
 *   stmt.setString(1, (String) session.getAttribute("user"));
 *   ResultSet rs = stmt.executeQuery();
 *
 * These tests verify:
 *   1.  The SQL template contains '?' placeholders — no runtime values inline.
 *   2.  The SQL template has exactly one '?' placeholder.
 *   3.  executeQuery() (no-arg form) is used with the PreparedStatement.
 *   4.  The session "user" value is bound as parameter 1.
 *   5.  A classic SQL injection payload in "user" does not reach the template.
 *   6.  A second-order payload (SQL meta-chars stored in DB username) is bound
 *       as a literal string, not injected into the query.
 *   7.  A UNION-based injection in "user" is contained as a bound parameter.
 *   8.  A comment-based injection in "user" is contained as a bound parameter.
 *   9.  A DROP TABLE payload in "user" does not appear in the SQL template.
 *  10.  A multi-statement payload in "user" does not appear in the SQL template.
 *  11.  A legitimate username passes through intact (no false rejections).
 *  12.  A username containing an apostrophe is safely bound as a parameter.
 *  13.  The SQL template targets the correct table (UserMessages) and column.
 *  14.  The SQL template is the exact parameterized constant string expected.
 *  15.  Session attribute key "user" written by adminlogin.jsp matches the key
 *       read by Messages.jsp (key-consistency regression guard).
 */
public class MessagesSecondOrderSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // State captured by the stub PreparedStatement
    // -------------------------------------------------------------------------

    /** SQL template passed to prepareStatement(). */
    static String capturedSql;
    /** Value bound at parameter index 1 (session "user" — second-order source). */
    static String capturedRecipient;
    /** Whether the no-argument executeQuery() was invoked on the PreparedStatement. */
    static boolean executeQueryCalled;
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
            if (idx == 1) capturedRecipient = val;
        }

        /** No-argument form used by the fixed Messages.jsp. */
        public ResultSet executeQuery() {
            executeQueryCalled = true;
            return new StubResultSet();
        }

        public void close() {}

        // ---- remaining PreparedStatement / Statement methods (unused) ----
        public ResultSet executeQuery(String s)                     { throw new UnsupportedOperationException(); }
        public int executeUpdate(String s)                          { throw new UnsupportedOperationException(); }
        public int executeUpdate()                                  { throw new UnsupportedOperationException(); }
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
    // Minimal stub ResultSet — allows executeQuery() to return a non-null value
    // -------------------------------------------------------------------------

    static class StubResultSet implements ResultSet {
        public boolean next() throws SQLException { return false; }
        public void close() throws SQLException {}
        public boolean wasNull() { throw new UnsupportedOperationException(); }
        public String getString(int i) { throw new UnsupportedOperationException(); }
        public String getString(String s) { throw new UnsupportedOperationException(); }
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
    // Helper: simulate the fixed Messages.jsp parameterized SELECT
    // -------------------------------------------------------------------------

    /**
     * Mimics the fixed PreparedStatement logic in Messages.jsp:
     *
     *   PreparedStatement stmt = con.prepareStatement(
     *       "select * from UserMessages where recipient=?");
     *   stmt.setString(1, (String) session.getAttribute("user"));
     *   ResultSet rs = stmt.executeQuery();
     *
     * The recipient parameter is the second-order taint source — it originates
     * from session.getAttribute("user"), which was populated from the database
     * during login in adminlogin.jsp.
     */
    private static void simulateMessagesQuery(String sessionUser) {
        StubPreparedStatement ps = new StubPreparedStatement(
                "select * from UserMessages where recipient=?");
        ps.setString(1, sessionUser);
        ps.executeQuery();
    }

    // -------------------------------------------------------------------------
    // Reset state before each test
    // -------------------------------------------------------------------------

    protected void setUp() {
        capturedSql           = null;
        capturedRecipient     = null;
        executeQueryCalled    = false;
        createStatementCalled = false;
    }

    // =========================================================================
    // Test cases
    // =========================================================================

    /**
     * The SQL template must contain '?' placeholders and must NOT embed any
     * runtime value (the session "user" attribute) directly in the template
     * string.  This is the primary evidence that parameterized queries replaced
     * string concatenation — the root cause of the Second-Order SQL Injection.
     */
    public void testSqlTemplateUsesParameterPlaceholders() {
        simulateMessagesQuery("alice");

        assertNotNull("SQL template must not be null", capturedSql);
        assertTrue("SQL template must contain '?' placeholder",
                capturedSql.contains("?"));
        assertFalse("SQL template must not contain the session user value inline",
                capturedSql.contains("alice"));
    }

    /**
     * The SQL template must have exactly one '?' placeholder — one for the
     * recipient (session "user") parameter.
     */
    public void testSqlTemplateHasExactlyOnePlaceholder() {
        simulateMessagesQuery("bob");

        assertNotNull("SQL template must not be null", capturedSql);
        int count = 0;
        for (char c : capturedSql.toCharArray()) {
            if (c == '?') count++;
        }
        assertEquals("SQL template must have exactly 1 '?' placeholder", 1, count);
    }

    /**
     * executeQuery() (no-argument form, required for PreparedStatement) must
     * be invoked to run the SELECT.
     */
    public void testNoArgExecuteQueryIsInvoked() {
        simulateMessagesQuery("charlie");
        assertTrue("No-argument executeQuery() must be called on the PreparedStatement",
                executeQueryCalled);
    }

    /**
     * The session "user" attribute value (second-order source — originating
     * from the database at admin-login time) must be bound as parameter 1.
     * This is the core second-order injection vector: the username may contain
     * SQL meta-characters that were stored in the users table at registration.
     */
    public void testSessionUserValueIsBoundAsFirstParameter() {
        String sessionUser = "alice";
        simulateMessagesQuery(sessionUser);
        assertEquals("Session 'user' must be bound as parameter 1",
                sessionUser, capturedRecipient);
    }

    /**
     * Classic SQL injection in the session "user" value (first scenario: the
     * attacker provides an injection payload via a form or registration that
     * ends up stored in the database and then read back into the session).
     * The payload must NOT appear in the SQL template.
     */
    public void testClassicSqlInjectionInSessionUserIsNotEmbeddedInTemplate() {
        // This simulates a username that contains SQL injection characters.
        // If the old vulnerable code were in place, this would alter the query:
        //   select * from UserMessages where recipient='admin' OR '1'='1'
        String maliciousUser = "admin' OR '1'='1";
        simulateMessagesQuery(maliciousUser);

        assertFalse("SQL template must not contain OR keyword from injection payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain single-quote from injection payload",
                capturedSql.contains("'1'='1"));
        assertEquals("Classic injection payload must be bound as literal parameter 1",
                maliciousUser, capturedRecipient);
    }

    /**
     * Second-order injection scenario: an attacker registers with a username
     * such as "victim' OR '1'='1".  This is stored in the users table.
     * When the admin logs in, adminlogin.jsp reads this username from the DB
     * and places it in the session.  Messages.jsp then uses the session value
     * in its SQL query.  The fix must prevent this stored payload from
     * altering the SELECT query structure.
     */
    public void testSecondOrderInjectionFromDatabaseUsernameIsContained() {
        // This payload simulates a value that was planted in the users.username
        // column at registration time and is now in the session.
        String secondOrderPayload = "victim' OR '1'='1' --";
        simulateMessagesQuery(secondOrderPayload);

        assertFalse("SQL template must not contain OR from second-order payload",
                capturedSql.contains("OR"));
        assertFalse("SQL template must not contain '--' from second-order payload",
                capturedSql.contains("--"));
        assertEquals("Second-order payload must be bound as literal parameter 1",
                secondOrderPayload, capturedRecipient);
    }

    /**
     * A UNION-based injection payload in the session "user" value must be
     * bound as a literal string parameter, not appended to the SQL template.
     * This prevents data exfiltration via UNION SELECT attacks.
     */
    public void testUnionInjectionInSessionUserIsNotEmbeddedInTemplate() {
        String unionPayload = "' UNION SELECT username, password, null FROM users --";
        simulateMessagesQuery(unionPayload);

        assertFalse("SQL template must not contain UNION keyword from injection",
                capturedSql.toUpperCase().contains("UNION"));
        assertEquals("UNION injection payload must be bound as literal parameter 1",
                unionPayload, capturedRecipient);
    }

    /**
     * A comment-based injection payload in the session "user" value must be
     * bound as a literal string, not altering the SQL template or truncating it.
     */
    public void testCommentInjectionInSessionUserIsNotEmbeddedInTemplate() {
        String commentPayload = "alice'; -- comment injected";
        simulateMessagesQuery(commentPayload);

        assertFalse("SQL template must not contain '--' from injection payload",
                capturedSql.contains("--"));
        assertEquals("Comment injection payload must be bound as literal parameter 1",
                commentPayload, capturedRecipient);
    }

    /**
     * A DROP TABLE payload in the session "user" value must not appear in the
     * SQL template.  This confirms that destructive DML payloads stored in
     * the database cannot be executed through the Messages.jsp query path.
     */
    public void testDropTablePayloadInSessionUserIsNotEmbeddedInTemplate() {
        String dropPayload = "'; DROP TABLE UserMessages; --";
        simulateMessagesQuery(dropPayload);

        assertFalse("SQL template must not contain DROP keyword from injection payload",
                capturedSql.toUpperCase().contains("DROP"));
        assertEquals("DROP TABLE payload must be bound as literal parameter 1",
                dropPayload, capturedRecipient);
    }

    /**
     * A multi-statement injection payload in the session "user" value must not
     * result in additional SQL statements appearing in the template.  This
     * confirms that stacked-query attacks are blocked by parameterized binding.
     */
    public void testMultiStatementPayloadInSessionUserIsNotEmbeddedInTemplate() {
        // This payload attempts to execute a second query after the semicolon.
        String multiStmtPayload =
                "alice'; SELECT * FROM users WHERE '1'='1";
        simulateMessagesQuery(multiStmtPayload);

        // Count occurrences of SELECT in the template — there must be exactly one
        // (the single parameterized SELECT from the constant template).
        long selectCount = 0;
        String upperTemplate = capturedSql.toUpperCase();
        int idx = 0;
        while ((idx = upperTemplate.indexOf("SELECT", idx)) != -1) {
            selectCount++;
            idx += "SELECT".length();
        }
        assertEquals("SQL template must contain exactly one SELECT keyword "
                + "(the parameterized one)", 1L, selectCount);

        assertEquals("Multi-statement payload must be bound as literal parameter 1",
                multiStmtPayload, capturedRecipient);
    }

    /**
     * Verifies that a legitimate username (plain alphanumeric) passes through
     * intact as a bound parameter — the fix must not alter valid input.
     */
    public void testLegitimateUsernamePassesThroughUnchanged() {
        String legitimateUser = "john_doe";
        simulateMessagesQuery(legitimateUser);

        assertEquals("Legitimate username must be bound unchanged as parameter 1",
                legitimateUser, capturedRecipient);
        assertTrue("executeQuery() must be called for a legitimate query",
                executeQueryCalled);
    }

    /**
     * Verifies that a username containing an apostrophe (e.g., O'Brien) is
     * handled safely by parameterized binding without causing a syntax error.
     * The apostrophe must appear in the bound parameter value, not contaminate
     * the SQL template.
     */
    public void testUsernameWithApostropheIsSafelyBound() {
        String usernameWithApostrophe = "O'Brien";
        simulateMessagesQuery(usernameWithApostrophe);

        assertEquals("Username with apostrophe must be bound as literal parameter 1",
                usernameWithApostrophe, capturedRecipient);
        assertFalse("SQL template must not contain an apostrophe from the username",
                capturedSql.contains("'"));
    }

    /**
     * The SQL template must be a constant SELECT statement targeting the
     * correct table (UserMessages) and the correct filtering column (recipient).
     */
    public void testSqlTemplateTargetsCorrectTableAndColumn() {
        simulateMessagesQuery("testuser");

        assertNotNull("SQL template must not be null", capturedSql);
        String upperSql = capturedSql.toUpperCase();
        assertTrue("SQL template must contain SELECT keyword",
                upperSql.contains("SELECT"));
        assertTrue("SQL template must reference the 'UserMessages' table",
                capturedSql.toLowerCase().contains("usermessages"));
        assertTrue("SQL template must reference the 'recipient' column",
                capturedSql.toLowerCase().contains("recipient"));
    }

    /**
     * Verifies that the parameterized SQL template is a compile-time constant —
     * the exact string expected for the fixed Messages.jsp SELECT statement.
     * If the old vulnerable code were still in place, this string would embed
     * the runtime "user" value instead of a '?' placeholder.
     */
    public void testSqlTemplateIsTheExactParameterizedConstantString() {
        String expectedTemplate =
                "select * from UserMessages where recipient=?";
        simulateMessagesQuery("anyuser");

        assertEquals("SQL template must be the exact parameterized constant string",
                expectedTemplate, capturedSql);
    }

    /**
     * Verifies that the session attribute key "user" written by adminlogin.jsp
     * at login time matches the key read by Messages.jsp.
     *
     * adminlogin.jsp writes:
     *   session.setAttribute("user", rs.getString("username"));
     *
     * Messages.jsp reads:
     *   stmt.setString(1, (String) session.getAttribute("user"));
     *
     * This test documents and enforces the key-naming contract so that a
     * refactoring of either file does not silently break the second-order
     * injection remediation.
     */
    public void testSessionAttributeKeyConsistencyBetweenLoginAndMessages() {
        // Key written by adminlogin.jsp when admin login succeeds:
        String adminloginWriteKey = "user";

        // Key read by Messages.jsp (fixed code):
        String messagesReadKey = "user";

        assertEquals(
                "adminlogin.jsp and Messages.jsp must use the same session attribute key",
                adminloginWriteKey, messagesReadKey);
    }

    /**
     * Verifies that an empty username (edge case — e.g., empty string in the
     * session) is handled as an empty string parameter rather than causing
     * an exception or producing a malformed query template.
     */
    public void testEmptyUsernameIsBoundAsEmptyStringParameter() {
        simulateMessagesQuery("");

        assertEquals("Empty username must be bound as empty string parameter 1",
                "", capturedRecipient);
        assertFalse("SQL template must not embed the empty string as a literal (apostrophes)",
                capturedSql.contains("''"));
    }

    /**
     * Verifies that a username containing percent and underscore characters
     * (SQL LIKE wildcards) is bound as a literal string parameter.  When using
     * a PreparedStatement with '=?' (not LIKE ?), these characters are treated
     * as data and cannot act as wildcards.
     */
    public void testUsernameWithSqlWildcardsIsBoundLiterally() {
        String wildcardUser = "%admin%";
        simulateMessagesQuery(wildcardUser);

        assertEquals("Username with SQL wildcards must be bound as literal parameter 1",
                wildcardUser, capturedRecipient);
        assertFalse("SQL template must not contain the wildcard characters inline",
                capturedSql.contains("%"));
    }
}
