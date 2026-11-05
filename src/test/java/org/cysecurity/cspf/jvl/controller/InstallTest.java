package org.cysecurity.cspf.jvl.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Properties;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import junit.framework.TestCase;

/**
 * Verifies that the Install servlet (which can DROP DATABASE) requires an
 * authenticated admin session once the application has been installed.
 */
public class InstallTest extends TestCase {

    private File configFile;
    private Install servlet;
    private int errorCode;
    private StringWriter body;

    @Override
    protected void setUp() throws Exception {
        configFile = File.createTempFile("config", ".properties");
        errorCode = -1;
        body = new StringWriter();
        servlet = new Install();
        servlet.init((ServletConfig) proxy(ServletConfig.class, new InvocationHandler() {
            public Object invoke(Object p, Method m, Object[] a) {
                if (m.getName().equals("getServletContext")) {
                    return proxy(ServletContext.class, new InvocationHandler() {
                        public Object invoke(Object p2, Method m2, Object[] a2) {
                            return m2.getName().equals("getRealPath") ? configFile.getAbsolutePath() : null;
                        }
                    });
                }
                return null;
            }
        }));
    }

    @Override
    protected void tearDown() {
        configFile.delete();
    }

    private static Object proxy(Class<?> type, InvocationHandler h) {
        return Proxy.newProxyInstance(InstallTest.class.getClassLoader(), new Class<?>[]{type}, h);
    }

    private void writeConfig(boolean installed) throws Exception {
        Properties p = new Properties();
        p.setProperty("dburl", "jdbc:mysql://original:3306/");
        p.setProperty("jdbcdriver", "original.Driver");
        p.setProperty("dbuser", "u");
        p.setProperty("dbpass", "p");
        p.setProperty("dbname", "originaldb");
        p.setProperty("siteTitle", "t");
        if (installed) {
            p.setProperty("installed", "true");
        }
        FileOutputStream out = new FileOutputStream(configFile);
        p.store(out, null);
        out.close();
    }

    private Properties readConfig() throws Exception {
        Properties p = new Properties();
        FileInputStream in = new FileInputStream(configFile);
        p.load(in);
        in.close();
        return p;
    }

    /** privilege == null means "no session at all". */
    private HttpServletRequest request(final String privilege) {
        final HttpSession session = privilege == null ? null : (HttpSession) proxy(HttpSession.class,
                new InvocationHandler() {
                    public Object invoke(Object p, Method m, Object[] a) {
                        return m.getName().equals("getAttribute") ? privilege : null;
                    }
                });
        return (HttpServletRequest) proxy(HttpServletRequest.class, new InvocationHandler() {
            public Object invoke(Object p, Method m, Object[] a) {
                if (m.getName().equals("getSession")) {
                    return session;
                }
                if (m.getName().equals("getParameter")) {
                    // "0" makes setup() a no-op so no database is ever contacted
                    return "setup".equals(a[0]) ? "0" : "attackervalue";
                }
                return null;
            }
        });
    }

    private HttpServletResponse response() {
        return (HttpServletResponse) proxy(HttpServletResponse.class, new InvocationHandler() {
            public Object invoke(Object p, Method m, Object[] a) {
                if (m.getName().equals("sendError")) {
                    errorCode = ((Integer) a[0]).intValue();
                } else if (m.getName().equals("getWriter")) {
                    return new PrintWriter(body, true);
                }
                return null;
            }
        });
    }

    public void testInstalledWithoutSessionIsForbiddenAndConfigUntouched() throws Exception {
        writeConfig(true);
        servlet.doPost(request(null), response());
        assertEquals(HttpServletResponse.SC_FORBIDDEN, errorCode);
        Properties p = readConfig();
        assertEquals("originaldb", p.getProperty("dbname"));
        assertEquals("original.Driver", p.getProperty("jdbcdriver"));
    }

    public void testInstalledWithNonAdminSessionIsForbidden() throws Exception {
        writeConfig(true);
        servlet.doGet(request("user"), response());
        assertEquals(HttpServletResponse.SC_FORBIDDEN, errorCode);
        assertEquals("originaldb", readConfig().getProperty("dbname"));
    }

    public void testInstalledWithAdminSessionIsAllowed() throws Exception {
        writeConfig(true);
        servlet.doPost(request("admin"), response());
        assertEquals(-1, errorCode);
        assertEquals("attackervalue", readConfig().getProperty("dbname"));
    }

    public void testFirstTimeInstallIsAllowedBeforeAnyAdminExists() throws Exception {
        writeConfig(false);
        servlet.doPost(request(null), response());
        assertEquals(-1, errorCode);
        assertTrue(body.toString().contains("Unable to install"));
    }
}
