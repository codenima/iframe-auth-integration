package dev.codenima.postservlet;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.JWK;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JWKSCache {
    private static final String JWKS_URL = OIDCConfig.JWKS_URL;
    private static Map<String, JWK> keyCache = new ConcurrentHashMap<>();
    private static long lastFetchTime = 0;
    private static final long CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

    public static JWK getKey(String keyId) throws Exception {
        if (shouldRefreshCache()) {
            refreshCache();
        }
        return keyCache.get(keyId);
    }

    private static boolean shouldRefreshCache() {
        return System.currentTimeMillis() - lastFetchTime > CACHE_DURATION || keyCache.isEmpty();
    }

    private static synchronized void refreshCache() throws Exception {
        // Only refresh if still needed after acquiring lock
        if (!shouldRefreshCache()) {
            return;
        }

        URL url = new URL(JWKS_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        
        try {
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                // Parse JWKS
                JWKSet jwkSet = JWKSet.parse(response.toString());
                
                // Update cache
                Map<String, JWK> newCache = new HashMap<>();
                for (JWK key : jwkSet.getKeys()) {
                    newCache.put(key.getKeyID(), key);
                }
                
                keyCache = newCache;
                lastFetchTime = System.currentTimeMillis();
            }
        } finally {
            conn.disconnect();
        }
    }
}