package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import junit.framework.TestCase;

/**
 * Regression test for the SQL injection in vulnerability/sqli/download_id.jsp.
 * No JSP engine is available to the unit tests, so the JSP source is inspected
 * to make sure the query is parameterized and the "fileid" request parameter
 * is never concatenated into the SQL text.
 */
public class DownloadIdJspTest extends TestCase {

    private static final String JSP_PATH =
            "src/main/webapp/vulnerability/sqli/download_id.jsp";

    private String source;

    protected void setUp() throws Exception {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new FileReader(new File(JSP_PATH)));
        try {
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } finally {
            r.close();
        }
        source = sb.toString();
    }

    public void testQueryUsesPreparedStatementWithPlaceholder() {
        assertTrue(source.contains(
                "prepareStatement(\"select * from FilesList where fileid=?\")"));
        assertTrue(source.contains("stmt.setInt(1, Integer.parseInt(fileid.trim()))"));
        assertTrue(source.contains("stmt.executeQuery()"));
    }

    public void testNoRawStatementOrConcatenatedSql() {
        assertFalse(source.contains("createStatement()"));
        assertFalse(source.contains("where fileid=\"+fileid"));
        assertFalse(source.contains("executeQuery(\""));
    }
}
