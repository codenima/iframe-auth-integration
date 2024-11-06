package dev.codenima.postservlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@WebServlet("/AppB")
public class AppBServlet extends HttpServlet {
    private static final String SESSION_TOKEN_KEY = "APP_B_TOKEN";
    private static final String STATE_PARAM = "state";
    private static final String CODE_PARAM = "code";
    
        
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        // Get the token from Application A
        String token = request.getParameter("token");
        
        if (token == null || token.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Token is required");
            return;
        }

        // Create or get the session
        HttpSession session = request.getSession(true);
        
        // Generate a state parameter for CSRF protection
        String state = generateState();
        
        // Store both the token and state in session
        session.setAttribute(SESSION_TOKEN_KEY, new TokenStorage(token));
        session.setAttribute(STATE_PARAM, state);

        // Build the IDP B URL with state parameter
        String idpUrl = buildIdpUrl(state);

        // Respond with HTML that includes both the stored token confirmation 
        // and the redirect to IDP B
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<!DOCTYPE html>");
        out.println("<html>");
        out.println("<head>");
        out.println("<title>Redirecting to IDP B</title>");
        out.println("</head>");
        out.println("<body>");
        out.println("<script type='text/javascript'>");
        // Optional: Add a small delay to ensure session is saved
        out.println("setTimeout(function() {");
        out.println("    window.location.href = '" + idpUrl + "';");
        out.println("}, 100);");
        out.println("</script>");
        out.println("</body>");
        out.println("</html>");
    }

    private String generateState() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String buildIdpUrl(String state) {
        // Configure these values based on your IDP B setup
        String idpBaseUrl = OIDCConfig.AUTHORIZATION;
        String clientId = OIDCConfig.CLIENT_ID;
        String redirectUri = "http://localhost:8080/postservlet/AppB"; // Your callback URL
        String scope = "openid profile email";

        return String.format("%s?" +
            "response_type=code" +
            "&client_id=%s" +
            "&redirect_uri=%s" +
            "&scope=%s" +
            "&state=%s",
            idpBaseUrl,
            clientId,
            URLEncoder.encode(redirectUri, StandardCharsets.UTF_8),
            URLEncoder.encode(scope, StandardCharsets.UTF_8),
            state);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No session found");
            return;
        }

        // 1. Verify state parameter
        String expectedState = (String) session.getAttribute(STATE_PARAM);
        String receivedState = request.getParameter(STATE_PARAM);
        
        if (expectedState == null || !expectedState.equals(receivedState)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid state parameter");
            return;
        }

        // 2. Get authorization code
        String code = request.getParameter(CODE_PARAM);
        if (code == null || code.trim().isEmpty()) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "No authorization code received");
            return;
        }

        try {
            // 3. Exchange code for tokens
            TokenResponse tokens = exchangeCodeForTokens(code);
            
            // 4. Validate ID Token
            validateIdToken(tokens.getIdToken());
            
            // 5. Store tokens in session
            session.setAttribute("access_token", tokens.getAccessToken());
            session.setAttribute("id_token", tokens.getIdToken());
            
            // 6. Retrieve user info using access token (optional)
            JsonObject userInfo = fetchUserInfo(tokens.getAccessToken());
            
            // 7. Create user session
            createUserSession(session, userInfo, tokens);
            
            // 8. Redirect to protected resource or homepage
            response.sendRedirect("/postservlet/home");
            
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, 
                "Authentication failed: " + e.getMessage());
        }
    }

    private TokenResponse exchangeCodeForTokens(String code) throws IOException {
        URL url = new URL(OIDCConfig.TOKEN_ENDPOINT);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);

            // Prepare token request parameters
            String parameters = String.format("grant_type=authorization_code" +
                "&code=%s" +
                "&redirect_uri=%s" +
                "&client_id=%s" +
                "&client_secret=%s",
                URLEncoder.encode(code, StandardCharsets.UTF_8),
                URLEncoder.encode(OIDCConfig.REDIRECT_URI, StandardCharsets.UTF_8),
                URLEncoder.encode(OIDCConfig.CLIENT_ID, StandardCharsets.UTF_8),
                URLEncoder.encode(OIDCConfig.CLIENT_SECRET, StandardCharsets.UTF_8));

            // Send token request
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = parameters.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            // Read response
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                
                // Parse JSON response
                return parseTokenResponse(response.toString());
            }
        } finally {
            conn.disconnect();
        }
    }

    private TokenResponse parseTokenResponse(String jsonResponse) {
        JsonObject jsonObject = JsonParser.parseString(jsonResponse).getAsJsonObject();
        TokenResponse tokenResponse = new TokenResponse();
        
        tokenResponse.setAccessToken(jsonObject.get("access_token").getAsString());
        tokenResponse.setIdToken(jsonObject.get("id_token").getAsString());
        tokenResponse.setTokenType(jsonObject.get("token_type").getAsString());
        tokenResponse.setExpiresIn(jsonObject.get("expires_in").getAsInt());
        
        if (jsonObject.has("refresh_token")) {
            tokenResponse.setRefreshToken(jsonObject.get("refresh_token").getAsString());
        }
        
        return tokenResponse;
    }

    private void validateIdToken(String idToken) throws Exception {
        // 1. Decode JWT
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new Exception("Invalid ID token format");
        }

        // 2. Parse header and payload
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        
        JsonObject header = JsonParser.parseString(headerJson).getAsJsonObject();
        JsonObject payload = JsonParser.parseString(payloadJson).getAsJsonObject();
        
        // 3. Validate signature (implement according to your IDP's signing method)
        validateSignature(idToken, header.get("alg").getAsString());


        // 4. Validate required claims
        validateTokenClaims(idToken);
    }

    private void validateSignature(String idToken, String algorithm) throws Exception {
        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            
            // Get the key ID from the JWT header
            String keyId = signedJWT.getHeader().getKeyID();
            if (keyId == null) {
                throw new Exception("No 'kid' header found in JWT");
            }
            
            // Get the public key from JWKS
            JWK jwk = JWKSCache.getKey(keyId);
            if (jwk == null) {
                throw new Exception("No matching key found in JWKS");
            }
            
            // Verify the algorithm matches
            if (!algorithm.equals(jwk.getAlgorithm().getName())) {
                throw new Exception("Algorithm mismatch");
            }
            
            // Convert JWK to public key
            PublicKey publicKey = null;
            if (jwk instanceof RSAKey) {
                publicKey = ((RSAKey) jwk).toPublicKey();
            } else if (jwk instanceof ECKey) {
                publicKey = ((ECKey) jwk).toPublicKey();
            } else {
                throw new Exception("Unsupported key type");
            }
            
            // Create appropriate verifier based on algorithm
            JWSVerifier verifier = createVerifier(publicKey, algorithm);
            
            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                throw new Exception("JWT signature verification failed");
            }
            
        } catch (ParseException e) {
            throw new Exception("Failed to parse JWT", e);
        } catch (JOSEException e) {
            throw new Exception("Failed to verify JWT signature", e);
        }
    }

    private JWSVerifier createVerifier(PublicKey publicKey, String algorithm) throws JOSEException {
        switch (algorithm.toUpperCase()) {
            case "RS256":
            case "RS384":
            case "RS512":
                return new RSASSAVerifier((RSAPublicKey) publicKey);
                
            case "ES256":
            case "ES384":
            case "ES512":
                return new ECDSAVerifier((ECPublicKey) publicKey);
                
            case "PS256":
            case "PS384":
            case "PS512":
                return new RSASSAVerifier((RSAPublicKey) publicKey, 
                        new HashSet<>(Arrays.asList(algorithm)));
                
            default:
                throw new JOSEException("Unsupported algorithm: " + algorithm);
        }
    }

    private void validateTokenClaims(String idToken) throws Exception {
        try {
            // Parse the JWT
            SignedJWT signedJWT = SignedJWT.parse(idToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            // Validate expiration
            Date expirationTime = claims.getExpirationTime();
            if (expirationTime == null || expirationTime.before(new Date())) {
                throw new Exception("JWT has expired");
            }
            
            // Validate not before
            Date notBeforeTime = claims.getNotBeforeTime();
            if (notBeforeTime != null && notBeforeTime.after(new Date())) {
                throw new Exception("JWT is not yet valid");
            }
            
            // Validate issued at
            Date issuedAt = claims.getIssueTime();
            if (issuedAt == null || issuedAt.after(new Date())) {
                throw new Exception("JWT issue time is invalid");
            }
            
            // Validate issuer
            String issuer = claims.getIssuer();
            if (!OIDCConfig.EXPECTED_ISSUER.equals(issuer)) {
                throw new Exception("Invalid issuer: " + issuer);
            }
            
            // Validate audience
            List<String> audiences = claims.getAudience();
            if (!audiences.contains(OIDCConfig.CLIENT_ID)) {
                throw new Exception("Invalid audience");
            }

        } catch (ParseException e) {
            throw new Exception("Failed to parse JWT", e);
        } catch (JOSEException e) {
            throw new Exception("Failed to verify JWT signature", e);
        }
    }

    private JsonObject fetchUserInfo(String accessToken) throws IOException {
        URL url = new URL(OIDCConfig.USERINFO_ENDPOINT);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                return JsonParser.parseString(response.toString()).getAsJsonObject();
            }
        } finally {
            conn.disconnect();
        }
    }

    private void createUserSession(HttpSession session, JsonObject userInfo, TokenResponse tokens) {
        // Store user information in session
        session.setAttribute("user_id", userInfo.get("sub").getAsString());
        session.setAttribute("email", userInfo.get("email").getAsString());
        session.setAttribute("name", userInfo.get("name").getAsString());
        
        // Store authentication time
        session.setAttribute("auth_time", System.currentTimeMillis());
        
        // Store token expiration
        session.setAttribute("token_expiration", 
            System.currentTimeMillis() + (tokens.getExpiresIn() * 1000));
    }
}