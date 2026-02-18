package com.securitybridge;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * JWT (JSON Web Token) validation using the Nimbus JOSE+JWT library.
 *
 * <p>Supports two signature families:</p>
 * <ul>
 *   <li><strong>HMAC</strong> — HS256, HS384, HS512 (symmetric shared secret)</li>
 *   <li><strong>RSA</strong> — RS256, RS384, RS512 (asymmetric public key)</li>
 * </ul>
 *
 * <h3>Claims Validation</h3>
 * After signature verification the following registered claims are checked
 * (when present in the token):
 * <ul>
 *   <li>{@code exp} — must not be in the past (with configurable clock skew)</li>
 *   <li>{@code nbf} — must not be in the future (with configurable clock skew)</li>
 *   <li>{@code iss} — must match expected issuer (if provided)</li>
 *   <li>{@code aud} — must contain expected audience (if provided)</li>
 * </ul>
 *
 * <h3>Thread Safety</h3>
 * Instances are thread-safe. All state is either immutable or confined
 * to method-local variables.
 *
 * <h3>Usage Examples</h3>
 * <pre>{@code
 * // HMAC validation
 * JwtValidator validator = new JwtValidator();
 * Map<String, Object> claims = validator.validateHmac(token, "my-256-bit-secret");
 *
 * // HMAC with issuer + audience constraints
 * Map<String, Object> claims = validator.validateHmac(
 *         token, secret, "auth-service", "my-api");
 *
 * // RSA validation (PEM-encoded public key)
 * Map<String, Object> claims = validator.validateRsa(token, rsaPublicKeyPem);
 * }</pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 — JSON Web Token</a>
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE+JWT</a>
 */
public class JwtValidator {

    private static final Logger LOGGER = Logger.getLogger(JwtValidator.class.getName());

    /** Supported HMAC algorithms. */
    private static final Set<JWSAlgorithm> HMAC_ALGORITHMS = Set.of(
            JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);

    /** Supported RSA algorithms. */
    private static final Set<JWSAlgorithm> RSA_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512);

    /** Default clock skew tolerance for exp/nbf checks (60 seconds). */
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;

    private final long clockSkewSeconds;

    // =========================================================================
    //  Construction
    // =========================================================================

    /**
     * Creates a validator with the default clock skew of 60 seconds.
     */
    public JwtValidator() {
        this(DEFAULT_CLOCK_SKEW_SECONDS);
    }

    /**
     * Creates a validator with a custom clock skew tolerance.
     *
     * @param clockSkewSeconds maximum allowed clock difference in seconds
     *                         (applied to both {@code exp} and {@code nbf})
     * @throws IllegalArgumentException if negative
     */
    public JwtValidator(long clockSkewSeconds) {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException(
                    "Clock skew must be non-negative (got " + clockSkewSeconds + ")");
        }
        this.clockSkewSeconds = clockSkewSeconds;
    }

    // =========================================================================
    //  HMAC Validation
    // =========================================================================

    /**
     * Validates a JWT signed with an HMAC algorithm (HS256/HS384/HS512).
     *
     * @param token  the compact JWT string
     * @param secret the shared secret (minimum 32 bytes for HS256)
     * @return parsed claims as a mutable map
     * @throws JwtValidationException if validation fails for any reason
     */
    public Map<String, Object> validateHmac(String token, String secret) {
        return validateHmac(token, secret, null, null);
    }

    /**
     * Validates a JWT signed with an HMAC algorithm, optionally enforcing
     * issuer and audience constraints.
     *
     * @param token            the compact JWT string
     * @param secret           the shared secret
     * @param expectedIssuer   required {@code iss} claim value, or null to skip
     * @param expectedAudience required {@code aud} claim value, or null to skip
     * @return parsed claims as a mutable map
     * @throws JwtValidationException if validation fails for any reason
     */
    public Map<String, Object> validateHmac(String token, String secret,
                                            String expectedIssuer, String expectedAudience) {
        ValidationUtils.requireNonEmpty(token, "token");
        ValidationUtils.requireNonEmpty(secret, "secret");

        SignedJWT signedJwt = parseToken(token);
        JWSAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();

        if (!HMAC_ALGORITHMS.contains(algorithm)) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.UNSUPPORTED_ALGORITHM,
                    "Expected HMAC algorithm but got " + algorithm.getName());
        }

        try {
            JWSVerifier verifier = new MACVerifier(secret.getBytes());
            verifySignature(signedJwt, verifier);
        } catch (JOSEException e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_SIGNATURE,
                    "HMAC verifier creation failed: " + e.getMessage(), e);
        }

        return extractAndValidateClaims(signedJwt, expectedIssuer, expectedAudience);
    }

    // =========================================================================
    //  RSA Validation
    // =========================================================================

    /**
     * Validates a JWT signed with an RSA algorithm (RS256/RS384/RS512).
     *
     * @param token        the compact JWT string
     * @param publicKeyPem the RSA public key in PEM format (Base64-encoded
     *                     DER wrapped in BEGIN/END markers) or raw Base64
     * @return parsed claims as a mutable map
     * @throws JwtValidationException if validation fails for any reason
     */
    public Map<String, Object> validateRsa(String token, String publicKeyPem) {
        return validateRsa(token, publicKeyPem, null, null);
    }

    /**
     * Validates a JWT signed with an RSA algorithm, optionally enforcing
     * issuer and audience constraints.
     *
     * @param token            the compact JWT string
     * @param publicKeyPem     the RSA public key in PEM or raw Base64 format
     * @param expectedIssuer   required {@code iss} claim value, or null to skip
     * @param expectedAudience required {@code aud} claim value, or null to skip
     * @return parsed claims as a mutable map
     * @throws JwtValidationException if validation fails for any reason
     */
    public Map<String, Object> validateRsa(String token, String publicKeyPem,
                                           String expectedIssuer, String expectedAudience) {
        ValidationUtils.requireNonEmpty(token, "token");
        ValidationUtils.requireNonEmpty(publicKeyPem, "publicKeyPem");

        SignedJWT signedJwt = parseToken(token);
        JWSAlgorithm algorithm = signedJwt.getHeader().getAlgorithm();

        if (!RSA_ALGORITHMS.contains(algorithm)) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.UNSUPPORTED_ALGORITHM,
                    "Expected RSA algorithm but got " + algorithm.getName());
        }

        RSAPublicKey rsaKey = decodeRsaPublicKey(publicKeyPem);

        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            verifySignature(signedJwt, verifier);
        } catch (Exception e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_SIGNATURE,
                    "RSA verifier creation failed: " + e.getMessage(), e);
        }

        return extractAndValidateClaims(signedJwt, expectedIssuer, expectedAudience);
    }

    // =========================================================================
    //  Internal — Parsing
    // =========================================================================

    /**
     * Parses the compact JWT string into a {@link SignedJWT}.
     */
    private SignedJWT parseToken(String token) {
        try {
            return SignedJWT.parse(token);
        } catch (ParseException e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.MALFORMED_TOKEN,
                    "Failed to parse JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the cryptographic signature.
     */
    private void verifySignature(SignedJWT jwt, JWSVerifier verifier) {
        try {
            if (!jwt.verify(verifier)) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.INVALID_SIGNATURE,
                        "JWT signature verification failed");
            }
        } catch (JOSEException e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_SIGNATURE,
                    "Signature verification error: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    //  Internal — Claims Extraction & Validation
    // =========================================================================

    /**
     * Extracts the claims set, validates temporal and identity claims,
     * and returns them as a plain map.
     */
    private Map<String, Object> extractAndValidateClaims(SignedJWT jwt,
                                                         String expectedIssuer,
                                                         String expectedAudience) {
        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.MALFORMED_TOKEN,
                    "Failed to extract claims: " + e.getMessage(), e);
        }

        Date now = new Date();
        long skewMillis = clockSkewSeconds * 1000;

        // --- Expiry (exp) ---
        Date expiration = claims.getExpirationTime();
        if (expiration != null) {
            if (new Date(now.getTime() - skewMillis).after(expiration)) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.EXPIRED,
                        "Token expired at " + expiration);
            }
        }

        // --- Not Before (nbf) ---
        Date notBefore = claims.getNotBeforeTime();
        if (notBefore != null) {
            if (new Date(now.getTime() + skewMillis).before(notBefore)) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.NOT_YET_VALID,
                        "Token not valid before " + notBefore);
            }
        }

        // --- Issuer (iss) ---
        if (expectedIssuer != null) {
            String issuer = claims.getIssuer();
            if (issuer == null || !expectedIssuer.equals(issuer)) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.INVALID_ISSUER,
                        "Expected issuer '" + expectedIssuer
                        + "' but got '" + issuer + "'");
            }
        }

        // --- Audience (aud) ---
        if (expectedAudience != null) {
            List<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(expectedAudience)) {
                throw new JwtValidationException(
                        JwtValidationException.Reason.INVALID_AUDIENCE,
                        "Expected audience '" + expectedAudience
                        + "' not found in " + audience);
            }
        }

        LOGGER.fine("JWT validation successful (sub=" + claims.getSubject() + ")");
        return claimsToMap(claims);
    }

    /**
     * Converts a {@link JWTClaimsSet} to a mutable {@link HashMap}, converting
     * {@link Date} values to epoch-second longs for easy downstream consumption.
     */
    private Map<String, Object> claimsToMap(JWTClaimsSet claims) {
        Map<String, Object> result = new HashMap<>();

        for (Map.Entry<String, Object> entry : claims.getClaims().entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Date) {
                result.put(entry.getKey(), ((Date) value).getTime() / 1000);
            } else {
                result.put(entry.getKey(), value);
            }
        }
        return result;
    }

    // =========================================================================
    //  Internal — RSA Key Decoding
    // =========================================================================

    /**
     * Decodes a PEM-formatted or raw Base64-encoded RSA public key.
     */
    private RSAPublicKey decodeRsaPublicKey(String pem) {
        try {
            String base64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) factory.generatePublic(spec);
        } catch (Exception e) {
            throw new JwtValidationException(
                    JwtValidationException.Reason.INVALID_KEY,
                    "Failed to decode RSA public key: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    //  Exception Class
    // =========================================================================

    /**
     * Thrown when JWT validation fails.
     *
     * <p>The {@link Reason} enum identifies the specific failure mode,
     * enabling callers to return appropriate HTTP status codes or
     * user-facing messages:</p>
     * <ul>
     *   <li>{@link Reason#MALFORMED_TOKEN} → 400 Bad Request</li>
     *   <li>{@link Reason#INVALID_SIGNATURE} → 401 Unauthorized</li>
     *   <li>{@link Reason#EXPIRED} → 401 Unauthorized</li>
     *   <li>{@link Reason#NOT_YET_VALID} → 401 Unauthorized</li>
     *   <li>{@link Reason#INVALID_ISSUER} → 403 Forbidden</li>
     *   <li>{@link Reason#INVALID_AUDIENCE} → 403 Forbidden</li>
     *   <li>{@link Reason#UNSUPPORTED_ALGORITHM} → 400 Bad Request</li>
     *   <li>{@link Reason#INVALID_KEY} → 500 Internal Server Error</li>
     * </ul>
     */
    public static class JwtValidationException extends RuntimeException {

        /** Categorises the specific validation failure. */
        public enum Reason {
            MALFORMED_TOKEN,
            INVALID_SIGNATURE,
            EXPIRED,
            NOT_YET_VALID,
            INVALID_ISSUER,
            INVALID_AUDIENCE,
            UNSUPPORTED_ALGORITHM,
            INVALID_KEY
        }

        private final Reason reason;

        public JwtValidationException(Reason reason, String message) {
            super(message);
            this.reason = reason;
        }

        public JwtValidationException(Reason reason, String message, Throwable cause) {
            super(message, cause);
            this.reason = reason;
        }

        /** Returns the categorised failure reason. */
        public Reason getReason() {
            return reason;
        }
    }
}
