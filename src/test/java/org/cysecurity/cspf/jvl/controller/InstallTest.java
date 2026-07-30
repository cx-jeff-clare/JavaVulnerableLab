package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;
import java.util.regex.Pattern;

/**
 * Tests for the CWE-15 (External Control of System/Config Setting) fix in Install.
 *
 * The vulnerability: user-supplied "dbname" request parameter was written directly
 * to the application's config.properties via config.setProperty("dbname", dbname)
 * without any validation, allowing an attacker to inject arbitrary values into the
 * configuration file.
 *
 * The fix: validate rawDbname against SAFE_DBNAME_PATTERN (^[A-Za-z0-9_]{1,64}$)
 * at the input boundary.  If validation fails the servlet returns HTTP 400 and
 * returns immediately — the tainted value never reaches setProperty().
 *
 * These unit tests verify the allowlist pattern logic directly, confirming that:
 *   1. Valid database names are accepted.
 *   2. Malicious / unexpected values are rejected.
 *   3. The pattern is anchored and cannot be bypassed.
 */
public class InstallTest extends TestCase {

    /**
     * The allowlist pattern extracted from Install.  Tested here independently
     * so that the validation logic can be verified without spinning up a full
     * servlet container.
     *
     * Must stay in sync with Install.SAFE_DBNAME_PATTERN.
     */
    private static final Pattern SAFE_DBNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_]{1,64}$");

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    /** Returns true when the pattern accepts the given input. */
    private boolean isValidDbname(String input) {
        if (input == null) {
            return false;
        }
        return SAFE_DBNAME_PATTERN.matcher(input).matches();
    }

    // -------------------------------------------------------------------------
    // Positive cases — values that MUST be accepted
    // -------------------------------------------------------------------------

    /** A plain lowercase name is valid. */
    public void testSimpleLowercaseNameIsAccepted() {
        assertTrue("lowercase database name must be accepted",
                isValidDbname("mydb"));
    }

    /** A plain uppercase name is valid. */
    public void testSimpleUppercaseNameIsAccepted() {
        assertTrue("uppercase database name must be accepted",
                isValidDbname("MYDB"));
    }

    /** Mixed-case name with underscores is valid. */
    public void testMixedCaseWithUnderscoreIsAccepted() {
        assertTrue("mixed-case name with underscore must be accepted",
                isValidDbname("My_Database_1"));
    }

    /** A name that is entirely digits is technically valid by the pattern. */
    public void testAllDigitNameIsAccepted() {
        assertTrue("all-digit database name must be accepted",
                isValidDbname("12345"));
    }

    /** A name that is exactly one character long is valid. */
    public void testSingleCharacterNameIsAccepted() {
        assertTrue("single-character database name must be accepted",
                isValidDbname("a"));
    }

    /** A name that is exactly 64 characters long is at the boundary and valid. */
    public void testExactly64CharacterNameIsAccepted() {
        // 64 'a' characters
        String name64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertEquals("test fixture length must be 64", 64, name64.length());
        assertTrue("64-character database name must be accepted",
                isValidDbname(name64));
    }

    // -------------------------------------------------------------------------
    // Negative cases — values that MUST be rejected
    // -------------------------------------------------------------------------

    /** A null dbname must be rejected (null check before pattern match). */
    public void testNullDbnameIsRejected() {
        assertFalse("null database name must be rejected",
                isValidDbname(null));
    }

    /** An empty string must be rejected ({1,64} requires at least one character). */
    public void testEmptyStringIsRejected() {
        assertFalse("empty string must be rejected",
                isValidDbname(""));
    }

    /** A name longer than 64 characters must be rejected. */
    public void testNameLongerThan64CharsIsRejected() {
        // 65 'a' characters
        String name65 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assertEquals("test fixture length must be 65", 65, name65.length());
        assertFalse("name longer than 64 characters must be rejected",
                isValidDbname(name65));
    }

    /**
     * A name containing a dot (e.g. used to escape to a parent directory or
     * to reference another schema in some DBMS dialects) must be rejected.
     */
    public void testDotInNameIsRejected() {
        assertFalse("database name with dot must be rejected",
                isValidDbname("my.db"));
    }

    /**
     * A name containing a forward slash (path traversal attempt) must be
     * rejected.
     */
    public void testSlashInNameIsRejected() {
        assertFalse("database name with slash must be rejected",
                isValidDbname("../../etc/passwd"));
    }

    /**
     * A name containing a newline (properties-file injection: a newline
     * allows the attacker to write arbitrary key=value pairs into
     * config.properties) must be rejected.
     */
    public void testNewlineInNameIsRejected() {
        // Use escape sequence to avoid a literal control byte in source
        assertFalse("database name with newline must be rejected",
                isValidDbname("db\nmalicious=value"));
    }

    /**
     * A name containing a carriage return (properties-file injection variant)
     * must be rejected.
     */
    public void testCarriageReturnInNameIsRejected() {
        assertFalse("database name with carriage return must be rejected",
                isValidDbname("db\rmalicious=value"));
    }

    /**
     * A name containing an equals sign (direct properties-file injection:
     * "dbname=x\nfoo=bar" would add an extra property) must be rejected.
     */
    public void testEqualsSignInNameIsRejected() {
        assertFalse("database name with equals sign must be rejected",
                isValidDbname("db=hacked"));
    }

    /**
     * A name with a space character must be rejected; spaces are not valid in
     * MySQL/PostgreSQL database names and could be used in further injection
     * payloads.
     */
    public void testSpaceInNameIsRejected() {
        assertFalse("database name with space must be rejected",
                isValidDbname("my database"));
    }

    /**
     * A name containing a semicolon (SQL injection variant) must be rejected.
     */
    public void testSemicolonInNameIsRejected() {
        assertFalse("database name with semicolon must be rejected",
                isValidDbname("mydb; DROP DATABASE mydb; --"));
    }

    /**
     * A name containing a single quote (SQL injection — dbname is used via
     * string concatenation in CREATE/DROP DATABASE statements) must be
     * rejected.
     */
    public void testSingleQuoteInNameIsRejected() {
        assertFalse("database name with single quote must be rejected",
                isValidDbname("'; DROP DATABASE mydb; --"));
    }

    /**
     * A name containing a backtick (MySQL identifier quoting, used to escape
     * the identifier context) must be rejected.
     */
    public void testBacktickInNameIsRejected() {
        assertFalse("database name with backtick must be rejected",
                isValidDbname("`injected`"));
    }

    /**
     * The pattern must be fully anchored — a value that embeds a valid name
     * within a longer malicious string must not match.
     */
    public void testAnchoringPreventsPartialMatch() {
        // Without anchoring, "mydb" inside this string might partially match;
        // the ^ and $ anchors must prevent this.
        assertFalse("pattern must be fully anchored and not partially match",
                isValidDbname("mydb; malicious_suffix"));
    }

    /**
     * A name consisting only of underscores is valid by the pattern.
     */
    public void testUnderscoreOnlyNameIsAccepted() {
        assertTrue("underscore-only name must be accepted",
                isValidDbname("_"));
    }

    /**
     * A Unicode character outside the ASCII range must be rejected.
     */
    public void testUnicodeCharacterInNameIsRejected() {
        // Unicode character U+00E9 (é) — written as a Java Unicode escape
        assertFalse("database name with non-ASCII Unicode character must be rejected",
                isValidDbname("cafédb"));
    }

    /**
     * A name that is exactly one character over the limit (65 chars but all
     * valid alphanumeric) must be rejected to confirm the length cap is
     * enforced even when the character set is otherwise clean.
     */
    public void testLengthCapIsEnforcedIndependentlyOfCharacterSet() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 65; i++) {
            sb.append('x');
        }
        assertFalse("65-char all-valid-char name must still be rejected (exceeds length cap)",
                isValidDbname(sb.toString()));
    }
}
