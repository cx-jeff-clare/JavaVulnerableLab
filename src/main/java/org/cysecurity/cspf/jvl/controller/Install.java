    package org.cysecurity.cspf.jvl.controller;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Properties;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.cysecurity.cspf.jvl.model.HashMe;

/**
 *
 * @author breakthesec
 */
public class Install extends HttpServlet {

       static String dburl;
       static String jdbcdriver;
       static String dbuser;
       static String dbpass;
       static String dbname;
       static String siteTitle;
       static String adminuser;
       static String adminpass;

    /**
     * Allowlist pattern for SQL identifiers (database names).
     * Only alphanumeric characters and underscores are permitted.
     * This prevents SQL injection in DDL statements where parameterized
     * queries cannot be used (CREATE DATABASE, DROP DATABASE).
     */
    private static final Pattern VALID_IDENTIFIER = Pattern.compile("^[A-Za-z0-9_]{1,64}$");

    /**
     * Validates that the given name is a safe SQL identifier.
     * Only alphanumeric characters and underscores are allowed.
     *
     * @param name the identifier to validate
     * @return true if the identifier is safe, false otherwise
     */
    static boolean isValidIdentifier(String name) {
        return name != null && VALID_IDENTIFIER.matcher(name).matches();
    }
               
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
   
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String configPath=getServletContext().getRealPath("/WEB-INF/config.properties");
        
        //Getting Database Configuration from User Input
        dburl = request.getParameter("dburl");
        jdbcdriver = request.getParameter("jdbcdriver");
        dbuser = request.getParameter("dbuser");
        dbpass = request.getParameter("dbpass");
        dbname = request.getParameter("dbname");
        siteTitle= request.getParameter("siteTitle");
        adminuser= request.getParameter("adminuser");
        adminpass= HashMe.hashMe(request.getParameter("adminpass"));
        
        //Moifying Configuration Properties:
         Properties config=new Properties();
         config.load(new FileInputStream(configPath));
         config.setProperty("dburl",dburl);
         config.setProperty("jdbcdriver",jdbcdriver);
         config.setProperty("dbuser",dbuser);
         config.setProperty("dbpass",dbpass);
         config.setProperty("dbname",dbname);
         config.setProperty("siteTitle",siteTitle);
         FileOutputStream fileout = new FileOutputStream(configPath);
         config.store(fileout, null); 
         fileout.close();
         
        String i=request.getParameter("setup");
        response.setContentType("text/html;charset=UTF-8");
         try {
            PrintWriter out = response.getWriter();
            /* TODO output your page here. You may use following sample code. */
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Servlet install</title>");            
            out.println("</head>");
            out.println("<body>");
            if(setup(i))
            {
                out.print("successfully installed");
            }
            else
            {
                out.print("Something went wrong. Unable to install");
            }
            out.println("</body>");
            out.println("</html>");
        }
         catch(Exception e)
         {
             
         }
    }
     protected boolean setup(String i) throws IOException
    {

       if(i.equals("1"))
       {
                    // Validate dbname is a safe SQL identifier before using in DDL.
                    // DDL statements (CREATE/DROP DATABASE) do not support parameterized
                    // queries, so we enforce a strict allowlist: only alphanumeric
                    // characters and underscores are permitted (max 64 chars).
                    if (!isValidIdentifier(dbname)) {
                        return false;
                    }

                    try
                   {
                    Class.forName(jdbcdriver);
                    Connection con= DriverManager.getConnection(dburl,dbuser,dbpass);
                      if(con!=null && !con.isClosed())
                        {
                            //Database creation
                             Statement stmt = con.createStatement();
                             // dbname has been validated as a safe identifier above;
                             // backtick-quoting further ensures it is treated as an
                             // identifier rather than SQL syntax.
                             stmt.executeUpdate("DROP DATABASE IF EXISTS `" + dbname + "`");

                             stmt.executeUpdate("CREATE DATABASE `" + dbname + "`");
                             con.close();
                            con= DriverManager.getConnection(dburl+dbname,dbuser,dbpass);
                             stmt = con.createStatement();
                              if(!con.isClosed())
                            {
                                //User Table creation
                                stmt.executeUpdate("Create table users(ID int NOT NULL AUTO_INCREMENT, username varchar(30),email varchar(60), password varchar(60), about varchar(50),privilege varchar(20),avatar TEXT,secretquestion int,secret varchar(30),primary key (id))");
                                  // Use PreparedStatement for user-supplied adminuser and adminpass to prevent SQL injection
                                  PreparedStatement adminInsert = con.prepareStatement("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values (?,?,'admin@localhost','I am the admin of this application','default.jpg','admin',1,'rocky')");
                                  adminInsert.setString(1, adminuser);
                                  adminInsert.setString(2, adminpass);
                                  adminInsert.executeUpdate();
                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('victim','victim','victim@localhost','I am the victim of this application','default.jpg','user',1,'max')");
                                  stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('attacker','attacker','attacker@localhost','I am the attacker of this application','default.jpg','user',1,'bella')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('NEO','trinity','neo@matrix','I am the NEO','default.jpg','user',1,'sentinel')");
                                stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('trinity','NEO','trinity@matrix','it is Trinity','default.jpg','user',1,'sentinel')");
                                 stmt.executeUpdate("INSERT into users(username, password, email,About,avatar, privilege,secretquestion,secret) values ('Anderson','java','anderson@1999','I am computer programmer','default.jpg','user',1,'C++')");
                               
                                  //Posts table creation                                  
                                  stmt.executeUpdate("create table posts(postid int NOT NULL AUTO_INCREMENT, content TEXT,title varchar(100), user varchar(30), primary key (postid))");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Feel free to ask any questions about Java Vulnerable Lab','First Post', 'admin')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello Guys, this is victim','Second Post', 'victim')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Hello This is attacker','Third Post', 'attacker')");
                               stmt.executeUpdate("INSERT into posts(content,title, user) values ('Trinity! Help!','Help','neo')");
                               
                               
                               stmt.executeUpdate("create table tdata(id int, page varchar(30))");
                               stmt.executeUpdate("Insert into tdata values(1,'ext1.html')");
                                stmt.executeUpdate("Insert into tdata values(2,'ext2.html')");
                                
                                //Messages Table Creation
                                stmt.executeUpdate("Create table Messages(msgid int NOT NULL AUTO_INCREMENT,name varchar(30),email varchar(60), msg varchar(500),primary key (msgid))");
                                stmt.executeUpdate("INSERT into Messages(name,email, msg) values ('TestUser','Test@localhost', 'Hi admin, how are you')");
                               
                                //User Messages Table Creation recipient, sender, email, msg
                                stmt.executeUpdate("Create table UserMessages(msgid int NOT NULL AUTO_INCREMENT,recipient varchar(30),sender varchar(30),subject varchar(60), msg varchar(500),primary key (msgid))");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('attacker','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
                                 stmt.executeUpdate("INSERT into UserMessages(recipient, sender, subject, msg) values ('victim','admin','Hi','Hi<br/> This is admin of this page. <br/> Welcome to Our Forum')");
              
                                
                                 //Credit Card Table Creation
                                stmt.executeUpdate("Create table cards(id int,cardno varchar(80), cvv varchar(6),expirydate varchar(15))");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('1','4000123456789010','123','12/2014')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('2','4111111111111111 ','321','7/2015')");
                                stmt.executeUpdate("INSERT into cards(id,cardno, cvv,expirydate) values ('3','5111111111111118','111','1/2017')");
                               
                                //Files List Table Creation
                                stmt.executeUpdate("Create table FilesList(fileid int NOT NULL AUTO_INCREMENT,path text,primary key (fileid))");
                                stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/doc1.pdf')");
                                 stmt.executeUpdate("INSERT into FilesList(path) values ('/docs/exampledoc.pdf')");
                                
                                return true;
                            }
                              return false;
                        }
                   }
                   catch(SQLException ex)
                   {
                      System.out.println("SQLException: " + ex.getMessage());
                     System.out.println("SQLState: " + ex.getSQLState());
                     System.out.println("VendorError: " + ex.getErrorCode());
                   }
                   catch(ClassNotFoundException ex)
                   {
                       System.out.print("JDBC Driver Missing:<br/>"+ex);
                   }
      
       }
        return false;
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}