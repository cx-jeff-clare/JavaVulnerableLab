package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

/**
 * Tests for Install.validateIdentifier() — the allowlist guard that prevents
 * SQL injection via the {@code dbname} request parameter.
 *
 * <p>Context: The Install servlet used to concatenate the user-supplied
 * {@code dbname} value directly into DDL statements such as:
 * <pre>
 *   stmt.executeUpdate("CREATE DATABASE " + dbname);
 *   stmt.executeUpdate("DROP DATABASE IF EXISTS " + dbname);
 * </pre>
 * Because DDL statements do not support JDBC {@code ?} placeholders, the fix
 * validates {@code dbname} at the input boundary using a strict identifier
 * allowlist (letters, digits, underscores; must start with a letter; max 64
 * chars) before the value ever reaches a Statement sink.
 *
 * <p>These tests verify:
 * <ol>
 *   <li>Legitimate database names pass validation and are returned unchanged.</li>
 *   <li>SQL injection payloads are rejected at the boundary.</li>
 *   <li>Null input is rejected.</li>
 *   <li>Empty / blank input is rejected.</li>
 *   <li>Names starting with a digit are rejected.</li>
 *   <li>Names with hyphens, spaces, quotes, semicolons, or comment markers
 *       are rejected.</li>
 *   <li>Names at exactly 64 characters (the maximum) are accepted.</li>
 *   <li>Names that exceed 64 characters are rejected.</li>
 * </ol>
 */
public class InstallSqlInjectionTest extends TestCase {

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    /**
     * Asserts that {@code validateIdentifier} throws
     * {@link IllegalArgumentException} for the given input.
     */
    private void assertRejected(String input, String description) {
        try {
            Install.validateIdentifier(input);
            fail("Expected IllegalArgumentException for " + description
                    + " but none was thrown");
        } catch (IllegalArgumentException expected) {
            // correct — malicious input was blocked at the boundary
        }
    }

    // -------------------------------------------------------------------------
    // POSITIVE CASES — valid identifiers should pass through unchanged
    // -------------------------------------------------------------------------

    /** Simple lowercase name is accepted. */
    public void testSimpleLowercaseNameIsAccepted() {
        String result = Install.validateIdentifier("mydb");
        assertEquals("Simple lowercase name must be returned unchanged", "mydb", result);
    }

    /** Simple uppercase name is accepted. */
    public void testSimpleUppercaseNameIsAccepted() {
        String result = Install.validateIdentifier("MYDB");
        assertEquals("Uppercase name must be returned unchanged", "MYDB", result);
    }

    /** Mixed-case name with digits and underscores is accepted. */
    public void testMixedCaseWithDigitsAndUnderscoresIsAccepted() {
        String result = Install.validateIdentifier("My_DB_2024");
        assertEquals("Mixed case with digits and underscores must be accepted",
                "My_DB_2024", result);
    }

    /** Single-character name starting with a letter is accepted. */
    public void testSingleLetterNameIsAccepted() {
        String result = Install.validateIdentifier("a");
        assertEquals("Single letter must be accepted", "a", result);
    }

    /** Name at exactly 64 characters is accepted (boundary value). */
    public void testNameAtMaxLengthIsAccepted() {
        // 64 characters: 1 letter + 63 alphanumeric characters
        String maxName = "a" + repeat("b", 63); // 64 chars total
        assertEquals("Name of exactly 64 characters must be accepted",
                64, maxName.length());
        String result = Install.validateIdentifier(maxName);
        assertEquals("64-char name must be returned unchanged", maxName, result);
    }

    // -------------------------------------------------------------------------
    // NEGATIVE CASES — attacks and invalid values must be rejected
    // -------------------------------------------------------------------------

    /** Null is rejected to prevent NullPointerException before it reaches SQL. */
    public void testNullIsRejected() {
        assertRejected(null, "null input");
    }

    /** Empty string is rejected. */
    public void testEmptyStringIsRejected() {
        assertRejected("", "empty string");
    }

    /** Whitespace-only string is rejected. */
    public void testWhitespaceOnlyIsRejected() {
        assertRejected("   ", "whitespace-only string");
    }

    /**
     * Classic SQL injection: trailing comment + drop.
     * e.g. {@code testdb; DROP DATABASE testdb --}
     */
    public void testSemicolonDropInjectionIsRejected() {
        assertRejected("testdb; DROP DATABASE testdb --",
                "semicolon + DROP injection");
    }

    /**
     * Classic SQL injection with single-quote to break out of a string context.
     * e.g. {@code ' OR '1'='1}
     */
    public void testSingleQuoteInjectionIsRejected() {
        assertRejected("' OR '1'='1", "single-quote OR injection");
    }

    /**
     * Double-hyphen SQL comment injection.
     * e.g. {@code mydb --}
     */
    public void testDoubleHyphenCommentInjectionIsRejected() {
        assertRejected("mydb --", "double-hyphen comment injection");
    }

    /**
     * Hash-character SQL comment (MySQL dialect).
     * e.g. {@code mydb # comment}
     */
    public void testHashCommentInjectionIsRejected() {
        assertRejected("mydb # comment", "hash-comment injection");
    }

    /**
     * UNION-based injection attempt in a database name.
     * e.g. {@code db UNION SELECT 1}
     */
    public void testUnionInjectionInDbnameIsRejected() {
        assertRejected("db UNION SELECT 1", "UNION SELECT injection");
    }

    /**
     * Space within the identifier is rejected (spaces are not allowed in
     * unquoted SQL identifiers and could form two-token attacks).
     */
    public void testSpaceWithinNameIsRejected() {
        assertRejected("my db", "identifier with embedded space");
    }

    /**
     * Hyphen within the identifier is rejected.
     */
    public void testHyphenWithinNameIsRejected() {
        assertRejected("my-db", "identifier with hyphen");
    }

    /**
     * Dollar sign is rejected (not a valid unquoted identifier character in all
     * databases and could confuse parsers).
     */
    public void testDollarSignIsRejected() {
        assertRejected("my$db", "identifier with dollar sign");
    }

    /**
     * Names starting with a digit must be rejected because SQL identifiers
     * must start with a letter (or underscore in some dialects, but we enforce
     * letter-only start for safety).
     */
    public void testNameStartingWithDigitIsRejected() {
        assertRejected("1mydb", "identifier starting with a digit");
    }

    /**
     * Names starting with an underscore are rejected by this allowlist.
     * While some databases allow them, our pattern requires a leading letter
     * to keep the allowlist conservative.
     */
    public void testNameStartingWithUnderscoreIsRejected() {
        assertRejected("_mydb", "identifier starting with underscore");
    }

    /**
     * Name exceeding 64 characters is rejected (MySQL max identifier length).
     */
    public void testNameExceedingMaxLengthIsRejected() {
        String tooLong = "a" + repeat("b", 64); // 65 chars
        assertEquals("Precondition: name must be 65 chars", 65, tooLong.length());
        assertRejected(tooLong, "identifier exceeding 64 characters");
    }

    /**
     * Backtick (MySQL identifier quoting character) must be rejected so that an
     * attacker cannot escape out of a backtick-quoted context.
     */
    public void testBacktickIsRejected() {
        assertRejected("my`db", "identifier with backtick");
    }

    /**
     * Double-quote (ANSI identifier quoting) must be rejected.
     */
    public void testDoubleQuoteIsRejected() {
        assertRejected("my\"db", "identifier with double-quote");
    }

    // -------------------------------------------------------------------------
    // STRUCTURAL VERIFICATION — ensure safeDbname never contains SQL metacharacters
    // -------------------------------------------------------------------------

    /**
     * After validation, the returned identifier must not contain any character
     * that is a SQL metacharacter.  This is a structural guarantee: if
     * validateIdentifier returns successfully, the result is safe to embed in
     * a DDL statement.
     */
    public void testReturnedIdentifierContainsNoSqlMetacharacters() {
        String[] validNames = {"mydb", "TestDB", "app_data_2024", "Db1"};
        String metacharacters = "' \" ; -- # /* */ ` \\ ( ) = < > !";

        for (String name : validNames) {
            String result = Install.validateIdentifier(name);
            for (char meta : new char[]{'\'', '"', ';', '-', '#', '/', '*', '`',
                    '\\', '(', ')', '=', '<', '>', '!'}) {
                assertFalse("Validated identifier '" + result
                                + "' must not contain metacharacter '" + meta + "'",
                        result.indexOf(meta) >= 0);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /** Returns {@code s} repeated {@code n} times. */
    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
