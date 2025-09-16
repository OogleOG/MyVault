package vault.licensing;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Offline, privacy-first license verification.
 * Token format: L1.<payloadBase64Url>.<signatureBase64Url>
 * payload JSON fields (strings): name, email, plan, issued, exp, machine (nullable), nonce
 * Signature: Ed25519 over the raw payload bytes.
 */
public final class LicenseManager {

    // === REPLACE THIS with your Ed25519 PUBLIC KEY (Base64, X.509 SubjectPublicKeyInfo encoding) ===
    private static final String PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAWZZN9saqXvPzGIc1gtzBWDGjCjp4SR89V9MWFfqk1E4=";

    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    public static final class Result {
        public final boolean valid;
        public final String reason;
        public final Map<String, String> payload;
        public Result(boolean valid, String reason, Map<String, String> payload) {
            this.valid = valid; this.reason = reason; this.payload = payload;
        }
    }

    public static Result verify(String license, String machineFingerprint) {
        try {
            if (license == null || !license.startsWith("L1.")) {
                return new Result(false, "Not a V1 license token", null);
            }
            String[] parts = license.split("\\.", 3);
            if (parts.length != 3) return new Result(false, "Malformed token", null);

            byte[] payloadBytes = B64URL_DEC.decode(parts[1]);
            byte[] sigBytes     = B64URL_DEC.decode(parts[2]);

            PublicKey pub = loadPublicKey(PUBLIC_KEY_B64);
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(payloadBytes);
            if (!sig.verify(sigBytes)) {
                return new Result(false, "Signature verification failed", null);
            }

            String json = new String(payloadBytes, StandardCharsets.UTF_8);
            Map<String,String> p = tinyJson(json);

            String plan  = p.get("plan");
            String exp   = p.get("exp");
            String bound = p.get("machine"); // may be null

            if (plan == null || plan.isEmpty()) return new Result(false, "Missing plan", p);
            if (exp != null && !exp.isEmpty()) {
                try {
                    if (LocalDate.parse(exp).isBefore(LocalDate.now())) {
                        return new Result(false, "License expired", p);
                    }
                } catch (DateTimeParseException ignore) {}
            }
            if (bound != null && machineFingerprint != null && !bound.equals(machineFingerprint)) {
                return new Result(false, "License bound to another device", p);
            }
            return new Result(true, "OK", p);
        } catch (Exception ex) {
            return new Result(false, "Error: " + ex.getMessage(), null);
        }
    }

    private static PublicKey loadPublicKey(String b64) throws Exception {
        byte[] raw = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(raw);
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }

    // ultra-tiny JSON object parser for flat string/null fields only
    private static Map<String,String> tinyJson(String s) {
        HashMap<String,String> m = new HashMap<>();
        s = s.trim();
        if (!(s.startsWith("{") && s.endsWith("}"))) return m;
        s = s.substring(1, s.length()-1).trim();
        if (s.isEmpty()) return m;
        // split on commas between k:v pairs (no nested objects supported)
        String[] parts = s.split("\\s*,\\s*");
        for (String part : parts) {
            int i = part.indexOf(':');
            if (i <= 0) continue;
            String k = unq(part.substring(0, i).trim());
            String v = unq(part.substring(i+1).trim());
            if ("null".equals(v)) v = null;
            m.put(k, v);
        }
        return m;
    }
    private static String unq(String t) {
        t = t.trim();
        if (t.startsWith("\"") && t.endsWith("\"") && t.length() >= 2) {
            return t.substring(1, t.length()-1);
        }
        return t;
    }
}
