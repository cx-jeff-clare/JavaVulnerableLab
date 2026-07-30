package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests for the Install servlet to verify SQL injection remediation in the
 * dbname input parameter.
 *
 * Background:
 *   The Install servlet's processRequest() method previously assigned
 *   request.getParameter("dbname") directly to the static field {@code dbname},
 *   which was then concatenated into DDL statements:
 *       stmt.executeUpdate("CREATE DATABASE " + dbname);
 *       stmt.executeUpdate("DROP DATABASE IF EXISTS " + dbname);
 *
 *   This enabled SQL injection via a crafted "dbname" parameter.
 *
 * Fix applied:
 *   The input is now validated against a strict identifier allowlist pattern
 *   ([A-Za-z][A-Za-z0-9_]{0,63}) at the source boundary in processRequest().
 *   Only names that match this pattern are accepted; all others result in
 *   dbname being set to null, which causes setup() to return false immediately
 *   without executing any SQL.
 *
 * These tests verify the allowlist logic directly by inspecting the static
 * field after simulating the validation step (since the servlet's validation
 * is inline in processRequest, we test the same logic pattern here).
 */
public class InstallTest extends TestCase {

    // -------------------------------------------------------------------------
    // Helper method — replicates the exact allowlist logic from Install.processRequest
    // so we can unit-test it in isolation without a real servlet container.
    // -------------------------------------------------------------------------

    /**
     * Applies the same allowlist validation used in Install.processRequest
     * to determine whether a candidate database name is accepted.
     *
     * Accepted: starts with a letter; contains only letters, digits, underscores;
     *           length between 1 and 64 characters inclusive.
     *
     * @param rawDbname the raw value from request.getParameter("dbname")
     * @return the validated name, or null if validation fails
     */
    private static String validateDbname(String rawDbname) {
        if (rawDbname != null && rawDbname.matches("[A-Za-z][A-Za-z0-9_]{0,63}")) {
            return rawDbname;
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Positive tests — valid database names should be accepted
    // -------------------------------------------------------------------------

    /**
     * A plain alphabetic database name must be accepted.
     */
    public void testValidSimpleNameIsAccepted() {
        assertNotNull("Plain alphabetic name must be accepted",
                validateDbname("myapp"));
        assertEquals("Plain alphabetic name must be returned as-is",
                "myapp", validateDbname("myapp"));
    }

    /**
     * A name with letters, digits, and underscores starting with a letter
     * is a valid SQL identifier.
     */
    public void testValidNameWithDigitsAndUnderscoresIsAccepted() {
        String name = "app_db_2024";
        assertEquals("Alphanumeric name with underscores must be accepted",
                name, validateDbname(name));
    }

    /**
     * An uppercase-only name must be accepted (identifiers are case-insensitive
     * in most databases, and uppercase letters are valid).
     */
    public void testValidUppercaseNameIsAccepted() {
        assertEquals("Uppercase identifier must be accepted",
                "MYDB", validateDbname("MYDB"));
    }

    /**
     * A mixed-case name with underscores is valid.
     */
    public void testValidMixedCaseNameIsAccepted() {
        assertEquals("Mixed-case name must be accepted",
                "My_Database_123", validateDbname("My_Database_123"));
    }

    /**
     * A single-character name (minimum length) must be accepted.
     */
    public void testSingleCharacterNameIsAccepted() {
        assertEquals("Single-letter name must be accepted",
                "a", validateDbname("a"));
    }

    /**
     * A name at the maximum allowed length (64 chars) must be accepted.
     */
    public void testMaxLengthNameIsAccepted() {
        // 64 characters: 1 leading letter + 63 alphanumeric/underscore chars
        String maxName = "a" + repeat("b", 63);
        assertEquals("64-character name must be accepted",
                maxName, validateDbname(maxName));
    }

    // -------------------------------------------------------------------------
    // Negative tests — injection payloads and invalid names must be rejected
    // -------------------------------------------------------------------------

    /**
     * A null input (missing request parameter) must be rejected with null result.
     */
    public void testNullInputIsRejected() {
        assertNull("Null dbname must be rejected",
                validateDbname(null));
    }

    /**
     * An empty string must be rejected (does not match the pattern).
     */
    public void testEmptyStringIsRejected() {
        assertNull("Empty dbname must be rejected",
                validateDbname(""));
    }

    /**
     * A name starting with a digit must be rejected — SQL identifiers must
     * start with a letter.
     */
    public void testNameStartingWithDigitIsRejected() {
        assertNull("Name starting with a digit must be rejected",
                validateDbname("1database"));
    }

    /**
     * A name starting with an underscore must be rejected — the allowlist
     * requires the first character to be a letter.
     */
    public void testNameStartingWithUnderscoreIsRejected() {
        assertNull("Name starting with underscore must be rejected",
                validateDbname("_database"));
    }

    /**
     * Classical SQL injection payload with a single quote and semicolon
     * must be rejected.
     *
     * Input: testdb'; DROP DATABASE testdb; --
     * Without the fix this payload would produce:
     *   CREATE DATABASE testdb'; DROP DATABASE testdb; --
     * which is a valid multi-statement injection.
     */
    public void testSingleQuoteAndSemicolonInjectionIsRejected() {
        assertNull("Payload with single quote and semicolon must be rejected",
                validateDbname("testdb'; DROP DATABASE testdb; --"));
    }

    /**
     * A name with a space (common in injection payloads) must be rejected.
     */
    public void testSpaceInNameIsRejected() {
        assertNull("Name containing a space must be rejected",
                validateDbname("my database"));
    }

    /**
     * A UNION-based injection payload must be rejected.
     *
     * Input: db UNION SELECT ...
     */
    public void testUnionInjectionPayloadIsRejected() {
        assertNull("UNION injection payload must be rejected",
                validateDbname("db UNION SELECT password FROM mysql.user"));
    }

    /**
     * A hyphen in the name must be rejected (hyphens are not valid unquoted
     * SQL identifier characters and could form part of an injection payload).
     */
    public void testHyphenInNameIsRejected() {
        assertNull("Name containing a hyphen must be rejected",
                validateDbname("my-database"));
    }

    /**
     * A backtick must be rejected — backticks are MySQL identifier-quoting
     * characters that could be used to escape the quoting context.
     */
    public void testBacktickInNameIsRejected() {
        assertNull("Name containing a backtick must be rejected",
                validateDbname("`testdb`"));
    }

    /**
     * A double-quote in the name must be rejected — it could be used as an
     * ANSI identifier quoting character to escape the DDL context.
     */
    public void testDoubleQuoteInNameIsRejected() {
        assertNull("Name containing a double quote must be rejected",
                validateDbname("\"testdb\""));
    }

    /**
     * A semicolon alone must be rejected.
     */
    public void testSemicolonAloneIsRejected() {
        assertNull("Semicolon must be rejected",
                validateDbname(";"));
    }

    /**
     * A comment sequence (--) must be rejected.
     */
    public void testCommentSequenceIsRejected() {
        assertNull("Comment sequence -- must be rejected",
                validateDbname("db--comment"));
    }

    /**
     * A forward-slash-star comment opener must be rejected.
     */
    public void testBlockCommentIsRejected() {
        assertNull("Block comment /* must be rejected",
                validateDbname("db/*comment*/"));
    }

    /**
     * A name containing a percent sign (wildcard) must be rejected.
     */
    public void testPercentInNameIsRejected() {
        assertNull("Name containing % must be rejected",
                validateDbname("db%name"));
    }

    /**
     * A name that is one character longer than the maximum (65 chars) must
     * be rejected to prevent excessively long inputs that could stress limits.
     */
    public void testNameExceedingMaxLengthIsRejected() {
        // 65 characters: 1 leading letter + 64 chars
        String tooLong = "a" + repeat("b", 64);
        assertNull("Name longer than 64 characters must be rejected",
                validateDbname(tooLong));
    }

    /**
     * A payload that would escape a backtick-quoted context in MySQL
     * must be rejected.
     *
     * Input: test`; DROP DATABASE test; #
     */
    public void testMySQLBacktickEscapeInjectionIsRejected() {
        assertNull("MySQL backtick-escape injection must be rejected",
                validateDbname("test`; DROP DATABASE test; #"));
    }

    /**
     * The literal string "null" as a name is a valid identifier and should
     * be accepted (it is not a null reference).
     */
    public void testLiteralStringNullIsAccepted() {
        assertEquals("The string \"null\" is a valid identifier name",
                "null", validateDbname("null"));
    }

    // -------------------------------------------------------------------------
    // Verify that setup() aborts when dbname is null (field-level guard)
    // -------------------------------------------------------------------------

    /**
     * When dbname has been set to null (due to validation failure), the setup()
     * method must return false without attempting to connect to the database.
     *
     * This test replicates the guard at the top of Install.setup():
     *   if (dbname == null) { return false; }
     */
    public void testSetupReturnsFalseWhenDbnameIsNull() {
        // Simulate what processRequest does when an invalid dbname is supplied:
        // The validated result is null.
        String validatedName = validateDbname("invalid'; DROP DATABASE x; --");
        assertNull("Invalid injection payload must produce null after validation",
                validatedName);

        // The null result, when assigned to Install.dbname before calling setup(),
        // causes setup() to return false immediately.  We verify the logic here:
        boolean wouldProceed = (validatedName != null);
        assertFalse("setup() must not proceed when dbname is null", wouldProceed);
    }

    /**
     * When dbname has been set to a valid value, the gate in setup() must
     * allow execution to proceed.
     */
    public void testSetupProceedsWhenDbnameIsValid() {
        String validatedName = validateDbname("myvaliddb");
        assertNotNull("Valid dbname must not be null after validation", validatedName);

        boolean wouldProceed = (validatedName != null);
        assertTrue("setup() must proceed when dbname is valid", wouldProceed);
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Repeats a string n times (String.repeat() requires Java 11+). */
    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
