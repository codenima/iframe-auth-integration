package dev.codenima.postservlet;

import java.io.Serializable;

public class TokenStorage implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String token;
    private final long timestamp;

    public TokenStorage(String token) {
        this.token = token;
        this.timestamp = System.currentTimeMillis();
    }

    public String getToken() {
        return token;
    }

    public long getTimestamp() {
        return timestamp;
    }
}