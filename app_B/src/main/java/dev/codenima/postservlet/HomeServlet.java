package dev.codenima.postservlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

import com.nimbusds.jose.shaded.gson.JsonElement;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.shaded.gson.JsonPrimitive;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@WebServlet("/home")
public class HomeServlet extends HttpServlet {
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.sendRedirect(request.getContextPath() + "/ApplicationB");
            return;
        }

        // Retrieve tokens and user info from session
        TokenStorage appAToken = (TokenStorage) session.getAttribute("APP_B_TOKEN");
        String idToken = (String) session.getAttribute("id_token");
        String accessToken = (String) session.getAttribute("access_token");
        
        // Decode and parse tokens
        JsonObject appATokenClaims = null;
        JsonObject idTokenClaims = null;
        
        try {
            if (appAToken != null) {
                appATokenClaims = decodeJwtPayload(appAToken.getToken());
            }
            
            if (idToken != null) {
                idTokenClaims = decodeJwtPayload(idToken);
            }
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Error processing tokens: " + e.getMessage());
            return;
        }

        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");

        try (PrintWriter out = response.getWriter()) {
            out.println("<!DOCTYPE html>");
            out.println("<html>");
            out.println("<head>");
            out.println("<title>Protected Home Page</title>");
            out.println("<style>");
            out.println("body { font-family: Arial, sans-serif; margin: 20px; }");
            out.println(".token-container { background: #f5f5f5; padding: 15px; margin: 10px 0; border-radius: 5px; }");
            out.println(".token-header { font-weight: bold; margin-bottom: 10px; }");
            out.println(".claim-item { margin: 5px 0; }");
            out.println(".timestamp { color: #666; font-size: 0.9em; }");
            out.println("</style>");
            out.println("</head>");
            out.println("<body>");
            
            // User info section
            out.println("<h2>Welcome, " + session.getAttribute("name") + "!</h2>");
            out.println("<p>Email: " + session.getAttribute("email") + "</p>");
            
            // Application A Token Section
            out.println("<div class='token-container'>");
            out.println("<div class='token-header'>Application A Token</div>");
            if (appATokenClaims != null) {
                out.println("<div class='timestamp'>Received at: " + 
                    new Date(appAToken.getTimestamp()) + "</div>");
                displayTokenClaims(out, appATokenClaims);
            } else {
                out.println("<p>No token received from Application A</p>");
            }
            out.println("</div>");
            
            // IDP B Token Section
            out.println("<div class='token-container'>");
            out.println("<div class='token-header'>IDP B ID Token</div>");
            if (idTokenClaims != null) {
                displayTokenClaims(out, idTokenClaims);
            } else {
                out.println("<p>No ID token available</p>");
            }
            out.println("</div>");
            
            // Session Info
            out.println("<div class='token-container'>");
            out.println("<div class='token-header'>Session Information</div>");
            out.println("<div class='claim-item'>Authentication Time: " + 
                new Date((Long) session.getAttribute("auth_time")) + "</div>");
            out.println("<div class='claim-item'>Session Expires: " + 
                new Date((Long) session.getAttribute("token_expiration")) + "</div>");
            out.println("</div>");
            
            // Logout button
            out.println("<form action='" + request.getContextPath() + "/logout' method='post'>");
            out.println("<input type='submit' value='Logout' style='margin-top: 20px;'>");
            out.println("</form>");
            
            out.println("</body>");
            out.println("</html>");
        }
    }
    
    private JsonObject decodeJwtPayload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new Exception("Invalid JWT format");
        }
        
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), 
            StandardCharsets.UTF_8);
        return JsonParser.parseString(payload).getAsJsonObject();
    }
    
    private void displayTokenClaims(PrintWriter out, JsonObject claims) {
        claims.entrySet().forEach(entry -> {
            out.println("<div class='claim-item'>");
            out.println("<strong>" + entry.getKey() + ":</strong> " + 
                formatClaimValue(entry.getKey(), entry.getValue()));
            out.println("</div>");
        });
    }
    
    private String formatClaimValue(String key, JsonElement element) {
        if (element.isJsonPrimitive()) {
            JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isNumber() && 
                (key.endsWith("_at") || key.endsWith("time"))) {
                // Format timestamp claims
                return new Date(primitive.getAsLong() * 1000).toString();
            }
            return primitive.getAsString();
        } else {
            // For arrays and objects, return the JSON string
            return element.toString();
        }
    }
}