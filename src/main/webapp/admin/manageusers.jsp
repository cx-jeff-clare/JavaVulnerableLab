 <%@ include file="/header.jsp" %>
  <%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.SQLException"%>
<%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.Connection"%>
<%@page import="org.apache.taglibs.standard.functions.Functions"%>

 <%
   Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
 if(request.getParameter("delete")!=null)
 {
     String user=request.getParameter("user");
     // Use PreparedStatement to prevent SQL injection
     PreparedStatement delStmt = con.prepareStatement("Delete from users where username=?");
     delStmt.setString(1, user);
     delStmt.executeUpdate();
 }
 %>
<form action="manageusers.jsp" method="POST">
<%
 PreparedStatement listStmt = con.prepareStatement("select * from users where privilege='user'");
 ResultSet rs=listStmt.executeQuery();
 while(rs.next())
 {
     // HTML-encode stored username before rendering to prevent Stored XSS (CWE-79)
     out.print("<input type='radio' name='user' value='" + Functions.escapeXml(rs.getString("username")) + "'/> " + Functions.escapeXml(rs.getString("username")) + "<br/>");
 }
 %>
<br/>
<input type="submit" value="Delete" name="delete"/>

</form>
<br/>
<a href="admin.jsp"> Back to Admin Panel</a>
 <%@ include file="/footer.jsp" %>