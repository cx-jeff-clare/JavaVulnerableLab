 <%@ include file="/header.jsp" %>
 <%@page import="java.sql.Connection"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.SQLException"%>

<%@page import="java.sql.ResultSetMetaData"%>
<%@page import="java.sql.ResultSet"%>
<%@ page import="java.util.*,java.io.*"%>
<%@ page import="org.cysecurity.cspf.jvl.model.DBConnect"%>


<%
if(session.getAttribute("isLoggedIn")!=null)
{
    %>
    Change Credit Card Info:<br/><br/>
		<form action="changeCardDetails.jsp" method="POST">
                    <table>
                        <tr><td>Card Number:</td><td><input type="text" name="cardno" value=""/> </td></tr>
               <tr><td> CVV:</td><td><input type="text" name="cvv" value=""/> </td></tr>
                <tr><td>Expiry Date:</td><td><input type="text" name="expirydate" value=""/> </td></tr>
		<tr><td/><td><input type="submit" name="action" value="add"/></td></tr>
                    </table>
		</form>
		<br/>
    <%
 Connection con=new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));

   String id=session.getAttribute("userid").toString();    //Gets User ID
   String action=request.getParameter("action");
   try
   {

    if(action!=null && action.equalsIgnoreCase("add") )
    {

        String cardno=request.getParameter("cardno");
        String cvv=request.getParameter("cvv");
        String expirydate=request.getParameter("expirydate");
        if(!cardno.equals("") && !cvv.equals("") && !expirydate.equals(""))
        {
         // Use PreparedStatement with parameterized query to prevent Second-Order SQL Injection (CWE-89).
         // The session "id" originates from DB data written at login (adminlogin.jsp) and is therefore
         // an untrusted, second-order input. Binding all values as typed parameters ensures no SQL
         // meta-characters in any of these values can alter the query structure.
         PreparedStatement stmt = con.prepareStatement(
             "INSERT INTO cards(id, cardno, cvv, expirydate) VALUES (?, ?, ?, ?)");
         stmt.setString(1, id);
         stmt.setString(2, cardno);
         stmt.setString(3, cvv);
         stmt.setString(4, expirydate);
         stmt.executeUpdate();
         out.print("<b style='color:green'> * Card details added *</b>");
        }
        else
        {
            out.print("<b style='color:red'>*  Please Fill all the details * </b>");
        }
    }

     out.print("<br/><br/><a href='"+path+"/myprofile.jsp?id="+id+"'>Return to Profile Page &gt;&gt;</a>"); 

    }
   catch(Exception e)
   {
       out.print(e);
   }
}
else
{
    out.print("Please login to view this page");
}

  %>
  
  <!-- CSRF  -->
<!-- Insecure Direct Object Reference 2 -->
  
 <%@ include file="/footer.jsp" %>