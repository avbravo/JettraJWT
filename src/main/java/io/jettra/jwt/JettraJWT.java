package io.jettra.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Native JWT implementation for the Jettra stack.
 * No external dependencies.
 * @author avbravo
 */
public class JettraJWT {

    private final String secret;
    private final long expirationTime;

    public JettraJWT(String secret, long expirationTimeMillis) {
        this.secret = secret;
        this.expirationTime = expirationTimeMillis;
    }

    public String generateToken(String username) {
        return generateToken(new HashMap<>(), username);
    }

    public String generateToken(Map<String, Object> extraClaims, String username) {
        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, Object> payload = new HashMap<>(extraClaims);
        payload.put("sub", username);
        payload.put("iat", System.currentTimeMillis() / 1000);
        payload.put("exp", (System.currentTimeMillis() + expirationTime) / 1000);

        String encodedHeader = base64UrlEncode(JettraJson.toJson(header));
        String encodedPayload = base64UrlEncode(JettraJson.toJson(payload));

        String signature = sign(encodedHeader + "." + encodedPayload, secret);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }

    public boolean isTokenValid(String token, String username) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return false;

            String headerPayload = parts[0] + "." + parts[1];
            String signature = parts[2];

            if (!signature.equals(sign(headerPayload, secret))) {
                return false;
            }

            Map<String, Object> payload = JettraJson.parse(base64UrlDecode(parts[1]));
            String subject = (String) payload.get("sub");
            long exp = ((Number) payload.get("exp")).longValue();

            return subject.equals(username) && exp * 1000 > System.currentTimeMillis();
        } catch (Exception e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        Map<String, Object> payload = getPayload(token);
        return (String) payload.get("sub");
    }

    public Date extractExpiration(String token) {
        Map<String, Object> payload = getPayload(token);
        long exp = ((Number) payload.get("exp")).longValue();
        return new Date(exp * 1000);
    }

    public Map<String, Object> getPayload(String token) {
        String[] parts = token.split("\\.");
        return JettraJson.parse(base64UrlDecode(parts[1]));
    }

    private String sign(String data, String secret) {
        try {
            Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256_HMAC.init(secret_key);
            return base64UrlEncode(sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException("Error signing JWT", e);
        }
    }

    private String base64UrlEncode(String data) {
        return base64UrlEncode(data.getBytes(StandardCharsets.UTF_8));
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private String base64UrlDecode(String data) {
        return new String(Base64.getUrlDecoder().decode(data), StandardCharsets.UTF_8);
    }
}
