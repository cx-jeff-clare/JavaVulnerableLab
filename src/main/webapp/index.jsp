 <%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ include file="header.jsp" %>
 <%
 if(session.getAttribute("user")!=null)
{
 %>
    Hello <c:out value="${sessionScope.user}"/>,
 <%
}
 %>
 Welcome to Java Vulnerable Lab !<br/><br/>
 A Deliberately vulnerable Web Application built on JAVA designed to teach Web Application Security. 
  <%@ include file="footer.jsp" %>