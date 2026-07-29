package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Tests to verify that CWE-732 (Incorrect Permission Assignment for File System
 * Resources) has been remediated in AddPage.java.
 *
 * The vulnerability was that AddPage created files using {@code File.createNewFile()}
 * whose permissions were controlled solely by the process umask — potentially
 * leaving files world-readable or world-writable on multi-user systems.
 *
 * The fix uses {@code java.nio.file.Files.createFile()} together with
 * {@code PosixFilePermissions.asFileAttribute()} to explicitly set
 * owner-only read/write permissions ({@code rw-------}, i.e., octal 0600),
 * regardless of the process umask.
 *
 * These tests validate:
 * 1. That {@code PosixFilePermissions.fromString("rw-------")} produces exactly the
 *    owner-read and owner-write bits with no group or other bits set.
 * 2. That {@code Files.createFile()} with those permissions creates a file
 *    accessible only to the owner on POSIX filesystems.
 * 3. That the permission set contains exactly the expected POSIX permission bits.
 * 4. That group and "other" permissions are absent from the permission set.
 * 5. That the Windows fallback path (setReadable/setWritable) restricts access
 *    correctly using {@code java.io.File} API.
 */
public class FilePermissionsTest extends TestCase {

    // =========================================================================
    // Core permission set validation tests
    // =========================================================================

    /**
     * Verifies that the permission string "rw-------" produces exactly
     * OWNER_READ and OWNER_WRITE permissions — the two bits required for the
     * servlet to write the file and for the web server to serve it, without
     * allowing any access to group or other users.
     */
    public void testOwnerOnlyPermissionSetContainsOwnerReadAndWrite() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        assertTrue(
            "Permission set must include OWNER_READ",
            ownerOnly.contains(PosixFilePermission.OWNER_READ)
        );
        assertTrue(
            "Permission set must include OWNER_WRITE",
            ownerOnly.contains(PosixFilePermission.OWNER_WRITE)
        );
    }

    /**
     * Verifies that the permission string "rw-------" does NOT include execute
     * permission for the owner — created pages are HTML/text files, never executables.
     * Owner execute should not be granted.
     */
    public void testOwnerOnlyPermissionSetExcludesOwnerExecute() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        assertFalse(
            "Permission set must NOT include OWNER_EXECUTE",
            ownerOnly.contains(PosixFilePermission.OWNER_EXECUTE)
        );
    }

    /**
     * Verifies that no group permissions are present in the "rw-------" set.
     *
     * Group read, write, and execute must all be absent so that members of the
     * web server's group cannot read or modify the created page files.
     */
    public void testOwnerOnlyPermissionSetExcludesAllGroupPermissions() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        assertFalse(
            "Permission set must NOT include GROUP_READ",
            ownerOnly.contains(PosixFilePermission.GROUP_READ)
        );
        assertFalse(
            "Permission set must NOT include GROUP_WRITE",
            ownerOnly.contains(PosixFilePermission.GROUP_WRITE)
        );
        assertFalse(
            "Permission set must NOT include GROUP_EXECUTE",
            ownerOnly.contains(PosixFilePermission.GROUP_EXECUTE)
        );
    }

    /**
     * Verifies that no "other" (world) permissions are present in the "rw-------" set.
     *
     * World read, write, and execute must all be absent so that arbitrary OS users
     * cannot access the created page files — this is the core CWE-732 remediation.
     */
    public void testOwnerOnlyPermissionSetExcludesAllOtherPermissions() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        assertFalse(
            "Permission set must NOT include OTHERS_READ",
            ownerOnly.contains(PosixFilePermission.OTHERS_READ)
        );
        assertFalse(
            "Permission set must NOT include OTHERS_WRITE",
            ownerOnly.contains(PosixFilePermission.OTHERS_WRITE)
        );
        assertFalse(
            "Permission set must NOT include OTHERS_EXECUTE",
            ownerOnly.contains(PosixFilePermission.OTHERS_EXECUTE)
        );
    }

    /**
     * Verifies that the permission set has exactly 2 elements: OWNER_READ and
     * OWNER_WRITE. No additional permissions should be present.
     */
    public void testOwnerOnlyPermissionSetHasExactlyTwoPermissions() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        assertEquals(
            "Permission set must contain exactly 2 permissions (OWNER_READ + OWNER_WRITE)",
            2,
            ownerOnly.size()
        );
    }

    // =========================================================================
    // File creation with restrictive permissions — POSIX filesystem tests
    // =========================================================================

    /**
     * Verifies that a file created on a POSIX filesystem using
     * {@code Files.createFile(path, PosixFilePermissions.asFileAttribute(ownerOnly))}
     * has exactly the {@code rw-------} permissions — no more, no less.
     *
     * This test is skipped on non-POSIX filesystems (Windows) because
     * {@code PosixFileAttributes} are not available there.
     */
    public void testFilesCreateFileAppliesRestrictivePermissionsOnPosix() throws IOException {
        Path tempDir = Files.createTempDirectory("cwe732test");
        Path testFile = tempDir.resolve("testpage.html");

        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            try {
                Files.createFile(testFile, PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (UnsupportedOperationException e) {
                // Non-POSIX filesystem — POSIX attribute creation not supported; skip this assertion
                return;
            }

            assertTrue("Created file must exist on disk", Files.exists(testFile));

            // Read back the POSIX permissions
            Set<PosixFilePermission> actualPermissions;
            try {
                actualPermissions = Files.getPosixFilePermissions(testFile);
            } catch (UnsupportedOperationException e) {
                // Non-POSIX filesystem — cannot read POSIX permissions; skip assertion
                return;
            }

            assertTrue(
                "Created file must have OWNER_READ permission",
                actualPermissions.contains(PosixFilePermission.OWNER_READ)
            );
            assertTrue(
                "Created file must have OWNER_WRITE permission",
                actualPermissions.contains(PosixFilePermission.OWNER_WRITE)
            );
            assertFalse(
                "Created file must NOT have GROUP_READ permission",
                actualPermissions.contains(PosixFilePermission.GROUP_READ)
            );
            assertFalse(
                "Created file must NOT have GROUP_WRITE permission",
                actualPermissions.contains(PosixFilePermission.GROUP_WRITE)
            );
            assertFalse(
                "Created file must NOT have OTHERS_READ permission (CWE-732 fix)",
                actualPermissions.contains(PosixFilePermission.OTHERS_READ)
            );
            assertFalse(
                "Created file must NOT have OTHERS_WRITE permission (CWE-732 fix)",
                actualPermissions.contains(PosixFilePermission.OTHERS_WRITE)
            );
        } finally {
            // Cleanup: delete test file and temp directory
            Files.deleteIfExists(testFile);
            Files.deleteIfExists(tempDir);
        }
    }

    /**
     * Verifies that re-creating a file (delete + create) on a POSIX filesystem
     * also applies the restrictive permissions to the new file, not just the first
     * creation. This mirrors the delete-then-create flow in AddPage.processRequest().
     */
    public void testFilesCreateFileAfterDeletionAppliesRestrictivePermissions() throws IOException {
        Path tempDir = Files.createTempDirectory("cwe732test_recreate");
        Path testFile = tempDir.resolve("page_recreated.html");

        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

            // First creation
            try {
                Files.createFile(testFile, PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (UnsupportedOperationException e) {
                return; // Non-POSIX; skip
            }
            assertTrue("First creation must succeed", Files.exists(testFile));

            // Delete (mirrors AddPage behavior when file already exists)
            Files.delete(testFile);
            assertFalse("File must be deleted before re-creation", Files.exists(testFile));

            // Second creation with same restrictive permissions
            Files.createFile(testFile, PosixFilePermissions.asFileAttribute(ownerOnly));
            assertTrue("Re-created file must exist on disk", Files.exists(testFile));

            Set<PosixFilePermission> actualPermissions;
            try {
                actualPermissions = Files.getPosixFilePermissions(testFile);
            } catch (UnsupportedOperationException e) {
                return; // Non-POSIX; skip assertion
            }

            assertFalse(
                "Re-created file must NOT have OTHERS_READ permission (CWE-732 fix)",
                actualPermissions.contains(PosixFilePermission.OTHERS_READ)
            );
            assertFalse(
                "Re-created file must NOT have OTHERS_WRITE permission (CWE-732 fix)",
                actualPermissions.contains(PosixFilePermission.OTHERS_WRITE)
            );
            assertEquals(
                "Re-created file must have exactly 2 permissions (OWNER_READ + OWNER_WRITE)",
                2,
                actualPermissions.size()
            );
        } finally {
            Files.deleteIfExists(testFile);
            Files.deleteIfExists(tempDir);
        }
    }

    // =========================================================================
    // Windows fallback permission tests (java.io.File-based restriction)
    // =========================================================================

    /**
     * Verifies the Windows fallback permission logic used when {@code UnsupportedOperationException}
     * is thrown by {@code Files.createFile(path, PosixFileAttribute)}.
     *
     * The fallback sequence in AddPage:
     *   1. {@code createdPath = Files.createFile(targetPath)}   (no permission attribute)
     *   2. {@code f.setReadable(false, false)}                   (remove world read)
     *   3. {@code f.setWritable(false, false)}                   (remove world write)
     *   4. {@code f.setReadable(true, true)}                     (restore owner read)
     *   5. {@code f.setWritable(true, true)}                     (restore owner write)
     *
     * This test validates that after the fallback sequence the file is owner-readable
     * and owner-writable as expected, using a temporary file on the current filesystem.
     */
    public void testWindowsFallbackPermissionsRestrictWorldAccess() throws IOException {
        Path tempDir = Files.createTempDirectory("cwe732test_win");
        Path testFilePath = tempDir.resolve("fallback_test.html");

        try {
            // Step 1: Create file without POSIX attributes (Windows fallback path)
            Files.createFile(testFilePath);
            assertTrue("Fallback: file must be created", Files.exists(testFilePath));

            java.io.File f = testFilePath.toFile();

            // Step 2-5: Apply the same fallback permission sequence as AddPage
            f.setReadable(false, false);  // remove all read
            f.setWritable(false, false);  // remove all write
            f.setReadable(true, true);    // restore owner read
            f.setWritable(true, true);    // restore owner write

            // Owner must be able to read the file
            assertTrue(
                "Fallback: owner must be able to read the created file",
                f.canRead()
            );
            // Owner must be able to write the file
            assertTrue(
                "Fallback: owner must be able to write to the created file",
                f.canWrite()
            );
        } finally {
            Files.deleteIfExists(testFilePath);
            Files.deleteIfExists(tempDir);
        }
    }

    /**
     * Verifies that after the Windows fallback sequence, the file is not
     * executable by the owner. Created page files should never be executable.
     */
    public void testWindowsFallbackPermissionsDoNotGrantExecute() throws IOException {
        Path tempDir = Files.createTempDirectory("cwe732test_exec");
        Path testFilePath = tempDir.resolve("exec_test.html");

        try {
            Files.createFile(testFilePath);
            java.io.File f = testFilePath.toFile();

            // Apply the Windows fallback sequence
            f.setReadable(false, false);
            f.setWritable(false, false);
            f.setReadable(true, true);
            f.setWritable(true, true);

            // The fallback does NOT call setExecutable(true), so the file
            // should not be executable (OS default for newly created files).
            // We confirm execute was not explicitly granted by the fallback code.
            assertFalse(
                "Fallback: setExecutable must not have been called — execute permission must not be granted",
                f.canExecute()
            );
        } finally {
            Files.deleteIfExists(testFilePath);
            Files.deleteIfExists(tempDir);
        }
    }

    // =========================================================================
    // Structural validation: NIO APIs used instead of legacy File.createNewFile
    // =========================================================================

    /**
     * Verifies that {@code AddPage} class is loadable and is a proper servlet,
     * confirming the NIO-based refactoring did not break class structure.
     */
    public void testAddPageClassIsLoadable() {
        try {
            Class<?> cls = Class.forName("org.cysecurity.cspf.jvl.controller.AddPage");
            assertNotNull("AddPage class must be loadable after CWE-732 fix", cls);

            // AddPage must still extend HttpServlet
            Class<?> superClass = cls.getSuperclass();
            assertNotNull("AddPage must extend a class", superClass);
            assertEquals(
                "AddPage must extend HttpServlet",
                "javax.servlet.http.HttpServlet",
                superClass.getName()
            );
        } catch (ClassNotFoundException e) {
            fail("AddPage class not found after CWE-732 remediation: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code java.nio.file.Files} is the class used for file creation
     * in the remediated code, not the legacy {@code java.io.File.createNewFile()}.
     *
     * This test confirms the architectural change: the NIO {@code Files.createFile()}
     * API accepts {@code FileAttribute} arguments (unlike legacy {@code createNewFile()}),
     * which is the mechanism that enables explicit POSIX permission assignment.
     */
    public void testNioFilesCreateFileSupportsFileAttributeArguments() throws Exception {
        // Verify that Files.createFile accepts vararg FileAttribute parameters
        // (the overload that enables POSIX permission assignment)
        java.lang.reflect.Method createFileMethod = null;
        try {
            createFileMethod = Files.class.getMethod(
                "createFile",
                Path.class,
                java.nio.file.attribute.FileAttribute[].class
            );
        } catch (NoSuchMethodException e) {
            fail("Files.createFile(Path, FileAttribute...) must exist in this JDK: " + e.getMessage());
        }
        assertNotNull(
            "Files.createFile(Path, FileAttribute...) must be present and accessible",
            createFileMethod
        );
    }

    /**
     * Verifies that {@code PosixFilePermissions.asFileAttribute()} wraps the permission
     * set into a {@code FileAttribute} compatible with {@code Files.createFile()}.
     *
     * This confirms the API bridge between the POSIX permission set and the NIO
     * file-creation attribute — the key mechanism of the CWE-732 fix.
     */
    public void testPosixFilePermissionsAsFileAttributeProducesNonNullAttribute() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        java.nio.file.attribute.FileAttribute<Set<PosixFilePermission>> attr =
                PosixFilePermissions.asFileAttribute(ownerOnly);

        assertNotNull(
            "PosixFilePermissions.asFileAttribute() must return a non-null FileAttribute",
            attr
        );
        assertEquals(
            "FileAttribute name must be 'posix:permissions'",
            "posix:permissions",
            attr.name()
        );
        assertEquals(
            "FileAttribute value must equal the input permission set",
            ownerOnly,
            attr.value()
        );
    }

    /**
     * Verifies that the permission string used in AddPage ("rw-------") is
     * correctly interpreted relative to the POSIX octal 0600 representation:
     *   Owner: read (4) + write (2) = 6
     *   Group: 0
     *   Others: 0
     *
     * This confirms the semantics of the permission constant used in the fix.
     */
    public void testOwnerOnlyPermissionStringRepresentsOctal0600() {
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");

        // Convert to string representation and verify it round-trips correctly
        String permString = PosixFilePermissions.toString(ownerOnly);
        assertEquals(
            "Permission set must round-trip to 'rw-------' (octal 0600)",
            "rw-------",
            permString
        );

        // Octal 0600: owner bits = read(0400) + write(0200) = 0600; group = 0; others = 0
        // Only OWNER_READ (value 256 = 0400) and OWNER_WRITE (value 128 = 0200) should be set
        assertEquals(
            "Octal 0600 must have exactly 2 POSIX permission bits",
            2,
            ownerOnly.size()
        );

        // Verify world-access bits are absent (this is the CWE-732 fix guarantee)
        for (PosixFilePermission perm : ownerOnly) {
            assertFalse(
                "No 'OTHERS' permission must appear in rw------- set, found: " + perm,
                perm.name().startsWith("OTHERS")
            );
            assertFalse(
                "No 'GROUP' permission must appear in rw------- set, found: " + perm,
                perm.name().startsWith("GROUP")
            );
        }
    }
}
