package org.cysecurity.cspf.jvl.controller;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import junit.framework.TestCase;

/**
 * Verifies that the Install servlet requires authentication before it touches
 * the configuration or the database.
 */
public class InstallTest extends TestCase {

    /** Install servlet with a fixed setup token instead of reading the environment. */
    private static class TestInstall extends Install {
        private final String token;
        TestInstall(String token) { this.token = token; }
        @Override
        protected String getInstallToken() { return token; }
    }

    private static HttpSession session(final Map<String, Object> attrs) {
        return (HttpSession) Proxy.newProxyInstance(
                InstallTest.class.getClassLoader(), new Class[]{HttpSession.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("getAttribute")) {
                            return attrs.get((String) args[0]);
                        }
                        return null;
                    }
                });
    }

    private static HttpServletRequest request(final HttpSession session, final String tokenParam) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                InstallTest.class.getClassLoader(), new Class[]{HttpServletRequest.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("getSession")) {
                            return session;
                        }
                        if (m.getName().equals("getParameter")) {
                            return "installToken".equals(args[0]) ? tokenParam : null;
                        }
                        return null;
                    }
                });
    }

    private static HttpServletResponse response(final int[] errorCode) {
        return (HttpServletResponse) Proxy.newProxyInstance(
                InstallTest.class.getClassLoader(), new Class[]{HttpServletResponse.class},
                new InvocationHandler() {
                    public Object invoke(Object proxy, Method m, Object[] args) {
                        if (m.getName().equals("sendError")) {
                            errorCode[0] = ((Integer) args[0]).intValue();
                        }
                        return null;
                    }
                });
    }

    public void testAnonymousRequestIsForbidden() throws Exception {
        int[] code = new int[1];
        // No session, no token: must be rejected before getServletContext() is reached.
        new TestInstall("secret").processRequest(request(null, null), response(code));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, code[0]);
    }

    public void testWrongTokenIsForbidden() throws Exception {
        int[] code = new int[1];
        new TestInstall("secret").processRequest(request(null, "wrong"), response(code));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, code[0]);
    }

    public void testNoConfiguredTokenDisablesTokenAccess() {
        assertFalse(new TestInstall(null).isAuthorized(request(null, "anything")));
        assertFalse(new TestInstall("").isAuthorized(request(null, "")));
    }

    public void testNonAdminSessionIsForbidden() {
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put("isLoggedIn", "1");
        attrs.put("privilege", "user");
        assertFalse(new TestInstall(null).isAuthorized(request(session(attrs), null)));
    }

    public void testCorrectTokenIsAuthorized() {
        assertTrue(new TestInstall("secret").isAuthorized(request(null, "secret")));
    }

    public void testAdminSessionIsAuthorized() {
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put("isLoggedIn", "1");
        attrs.put("privilege", "admin");
        assertTrue(new TestInstall(null).isAuthorized(request(session(attrs), null)));
    }
}
