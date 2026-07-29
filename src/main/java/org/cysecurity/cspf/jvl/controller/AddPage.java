/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.cysecurity.cspf.jvl.controller;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.taglibs.standard.functions.Functions;

/**
 *
 * @author breakthesec
 */
public class AddPage extends HttpServlet {

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
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try {
           String fileName=request.getParameter("filename");
           String content=request.getParameter("content");
           if(fileName!=null && content!=null)
           {
            String pagesDir=getServletContext().getRealPath("/pages");
            String filePath=pagesDir+"/"+fileName;
            // Use NIO Path for file creation with explicitly restrictive permissions (CWE-732).
            // Files.createFile() with PosixFilePermissions sets owner-read/write only (0600),
            // preventing other OS users from reading or writing the created file.
            Path targetPath = Paths.get(filePath);
            if(Files.exists(targetPath))
            {
                Files.delete(targetPath);
            }
            Path createdPath;
            try {
                // Attempt POSIX-aware creation with owner-only read/write permissions (rw-------)
                Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
                createdPath = Files.createFile(targetPath,
                        PosixFilePermissions.asFileAttribute(ownerOnly));
            } catch (UnsupportedOperationException e) {
                // Non-POSIX filesystem (e.g., Windows): create file and restrict
                // permissions explicitly to owner read/write, disabling world access.
                createdPath = Files.createFile(targetPath);
                File f = createdPath.toFile();
                f.setReadable(false, false);
                f.setWritable(false, false);
                f.setReadable(true, true);
                f.setWritable(true, true);
            }
            if(createdPath != null)
            {
                BufferedWriter bw = new BufferedWriter(
                        new OutputStreamWriter(Files.newOutputStream(createdPath), StandardCharsets.UTF_8));
                bw.write(content);
                bw.close();
                // HTML-encode fileName before rendering to prevent Stored XSS (CWE-79)
                String safeFileName = Functions.escapeXml(fileName);
                out.print("Successfully created the file: <a href='../pages/"+safeFileName+"'>"+safeFileName+"</a>");
            }
            else
            {
                out.print("Failed to create the file");
            }
           }
           else
           {
               out.print("filename or content Parameter is missing");
           }           
           
        } 
        catch(Exception e)
        {
            out.print(e);
        }
        finally {
            out.close();
        }
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
