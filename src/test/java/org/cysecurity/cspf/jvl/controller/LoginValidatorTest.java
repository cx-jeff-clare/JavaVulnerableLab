package org.cysecurity.cspf.jvl.controller;

import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import junit.framework.TestCase;

/**
 * Verifies that LoginValidator binds credentials as PreparedStatement
 * parameters instead of concatenating them into the SQL text.
 * A stub JDBC driver and java.lang.reflect.Proxy objects stand in for the
 * database and servlet container.
 */
public class LoginValidatorTest extends TestCase {

    private static final String EXPECTED_SQL =
            "select * from users where username=? and password=?";

    /** State recorded by the stub JDBC layer. */
    static final List<String> preparedSql = new ArrayList<String>();
    static final Map<Integer, String> boundParams = new HashMap<Integer, String>();
    static int createStatementCalls = 0;
    static boolean userFound = false;

    /** Stub JDBC driver returning proxy Connection objects. */
    public static class StubDriver implements Driver {
        static {
            try {
                DriverManager.registerDriver(new StubDriver());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        public Connection connect(String url, Properties info) {
            if (!acceptsURL(url)) {
                return null;
            }
            return (Connection) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[]{Connection.class},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            String name = m.getName();
                            if (name.equals("isClosed")) {
                                return Boolean.FALSE;
                            }
                            if (name.equals("createStatement")) {
                                createStatementCalls++;
                                throw new UnsupportedOperationException("raw Statement must not be used");
                            }
                            if (name.equals("prepareStatement")) {
                                preparedSql.add((String) args[0]);
                                return newPreparedStatement();
                            }
                            return defaultValue(m.getReturnType());
                        }
                    });
        }

        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:stubdb:");
        }

        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
            return new DriverPropertyInfo[0];
        }

        public int getMajorVersion() { return 1; }
        public int getMinorVersion() { return 0; }
        public boolean jdbcCompliant() { return false; }
        public Logger getParentLogger() { return Logger.getLogger("stub"); }
    }

    private static Object newPreparedStatement() {
        return Proxy.newProxyInstance(
                LoginValidatorTest.class.getClassLoader(),
                new Class<?>[]{java.sql.PreparedStatement.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        String name = m.getName();
                        if (name.equals("setString")) {
                            boundParams.put((Integer) args[0], (String) args[1]);
                            return null;
                        }
                        if (name.equals("executeQuery")) {
                            return newResultSet();
                        }
                        return defaultValue(m.getReturnType());
                    }
                });
    }

    private static ResultSet newResultSet() {
        return (ResultSet) Proxy.newProxyInstance(
                LoginValidatorTest.class.getClassLoader(),
                new Class<?>[]{ResultSet.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        String name = m.getName();
                        if (name.equals("next")) {
                            return Boolean.valueOf(userFound);
                        }
                        if (name.equals("getString")) {
                            return "1";
                        }
                        return defaultValue(m.getReturnType());
                    }
                });
    }

    private static Object defaultValue(Class<?> type) {
        if (type == boolean.class) {
            return Boolean.FALSE;
        }
        if (type == int.class) {
            return Integer.valueOf(0);
        }
        if (type == long.class) {
            return Long.valueOf(0L);
        }
        return null;
    }

    private File configFile;
    private final List<String> redirects = new ArrayList<String>();

    protected void setUp() throws Exception {
        preparedSql.clear();
        boundParams.clear();
        createStatementCalls = 0;
        userFound = false;
        redirects.clear();

        configFile = File.createTempFile("jvl-config", ".properties");
        FileWriter w = new FileWriter(configFile);
        w.write("dburl=jdbc:stubdb://localhost/\n");
        w.write("dbname=test\n");
        w.write("dbuser=u\n");
        w.write("dbpass=p\n");
        w.write("jdbcdriver=" + StubDriver.class.getName() + "\n");
        w.close();
    }

    protected void tearDown() {
        configFile.delete();
    }

    /** Servlet whose container context points at the temp config file. */
    private class TestableLoginValidator extends LoginValidator {
        public ServletContext getServletContext() {
            return (ServletContext) Proxy.newProxyInstance(
                    getClass().getClassLoader(), new Class<?>[]{ServletContext.class},
                    new InvocationHandler() {
                        public Object invoke(Object proxy, Method m, Object[] args) {
                            if (m.getName().equals("getRealPath")) {
                                return configFile.getAbsolutePath();
                            }
                            return defaultValue(m.getReturnType());
                        }
                    });
        }
    }

    private void login(final String username, final String password) throws Exception {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("username", username);
        params.put("password", password);

        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("getParameter")) {
                            return params.get((String) args[0]);
                        }
                        if (m.getName().equals("getSession")) {
                            return Proxy.newProxyInstance(
                                    getClass().getClassLoader(),
                                    new Class<?>[]{javax.servlet.http.HttpSession.class},
                                    new InvocationHandler() {
                                        public Object invoke(Object p, Method mm, Object[] a) {
                                            return defaultValue(mm.getReturnType());
                                        }
                                    });
                        }
                        return defaultValue(m.getReturnType());
                    }
                });

        HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletResponse.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("sendRedirect")) {
                            redirects.add((String) args[0]);
                            return null;
                        }
                        if (m.getName().equals("encodeURL")) {
                            return args[0];
                        }
                        return defaultValue(m.getReturnType());
                    }
                });

        new TestableLoginValidator().processRequest(request, response);
    }

    public void testQueryIsParameterized() throws Exception {
        login("alice", "secret");

        assertEquals(1, preparedSql.size());
        assertEquals(EXPECTED_SQL, preparedSql.get(0));
        assertEquals(0, createStatementCalls);
        assertEquals("alice", boundParams.get(1));
        assertEquals("secret", boundParams.get(2));
    }

    public void testSqlInjectionInUsernameIsBoundAsData() throws Exception {
        String payload = "admin' OR '1'='1' -- ";
        login(payload, "x");

        // SQL text must remain the constant template, with no payload in it.
        assertEquals(1, preparedSql.size());
        assertEquals(EXPECTED_SQL, preparedSql.get(0));
        assertFalse(preparedSql.get(0).contains("OR"));
        // The payload (trimmed by the servlet) is passed only as a bound value.
        assertEquals(payload.trim(), boundParams.get(1));
        assertEquals(0, createStatementCalls);
    }

    public void testSqlInjectionInPasswordIsBoundAsData() throws Exception {
        String payload = "' OR 1=1 --";
        login("alice", payload);

        assertEquals(EXPECTED_SQL, preparedSql.get(0));
        assertEquals(payload, boundParams.get(2));
    }

    public void testValidLoginRedirectsToIndex() throws Exception {
        userFound = true;
        login("alice", "secret");

        assertEquals(1, redirects.size());
        assertTrue(redirects.get(0).contains("location=/index.jsp"));
    }

    public void testInvalidLoginRedirectsToLogin() throws Exception {
        userFound = false;
        login("alice", "wrong");

        assertEquals(1, redirects.size());
        assertTrue(redirects.get(0).contains("location=/login.jsp"));
    }
}
