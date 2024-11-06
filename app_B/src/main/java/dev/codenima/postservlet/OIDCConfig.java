package dev.codenima.postservlet;

public class OIDCConfig {
    static final String TOKEN_ENDPOINT = "http://localhost:9090/realms/COLLAB/protocol/openid-connect/token";
    static final String AUTHORIZATION = "http://localhost:9090/realms/COLLAB/protocol/openid-connect/auth";
    static final String CLIENT_ID = "app_B_client";
    static final String CLIENT_SECRET = "txZSdBNFumLikG5NCrFD8u1JvpNhMLki";
    static final String REDIRECT_URI = "http://localhost:8080/postservlet/AppB";
    public static final String EXPECTED_ISSUER = "http://localhost:9090/realms/COLLAB";
    public static final String JWKS_URL = "http://localhost:9090/realms/COLLAB/protocol/openid-connect/certs";
    public static final String USERINFO_ENDPOINT = "http://localhost:9090/realms/COLLAB/protocol/openid-connect/userinfo";
}