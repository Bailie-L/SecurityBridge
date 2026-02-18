package com.securitybridge;

import com.securitybridge.JwtValidator.JwtValidationException;
import com.securitybridge.JwtValidator.JwtValidationException.Reason;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JwtValidator")
class JwtValidatorTest {

    private JwtValidator validator;
    private static final String HMAC_SECRET = "this-is-a-very-long-secret-key-for-hs256-testing!!";

    @BeforeEach
    void setUp() {
        validator = new JwtValidator();
    }

    // =========================================================================
    //  Helper — build signed JWTs for testing
    // =========================================================================

    private String buildHmacJwt(JWTClaimsSet claims) throws Exception {
        JWSSigner signer = new MACSigner(HMAC_SECRET.getBytes());
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(signer);
        return jwt.serialize();
    }


    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private String publicKeyToPem(RSAPublicKey key) {
        String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
    }

    // =========================================================================
    //  Constructor
    // =========================================================================

    @Nested
    @DisplayName("Constructor")
    class ConstructorTests {

        @Test
        @DisplayName("default clock skew accepted")
        void defaultClockSkew() {
            assertDoesNotThrow(() -> new JwtValidator());
        }

        @Test
        @DisplayName("custom positive clock skew accepted")
        void customClockSkew() {
            assertDoesNotThrow(() -> new JwtValidator(120));
        }

        @Test
        @DisplayName("zero clock skew accepted")
        void zeroClockSkew() {
            assertDoesNotThrow(() -> new JwtValidator(0));
        }

        @Test
        @DisplayName("negative clock skew rejected")
        void negativeClockSkew() {
            assertThrows(IllegalArgumentException.class, () -> new JwtValidator(-1));
        }
    }

    // =========================================================================
    //  HMAC Validation — Happy Path
    // =========================================================================

    @Nested
    @DisplayName("HMAC — valid tokens")
    class HmacValid {

        @Test
        @DisplayName("basic token with subject claim")
        void basicToken() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user-123")
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build();

            Map<String, Object> result = validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET);
            assertEquals("user-123", result.get("sub"));
        }

        @Test
        @DisplayName("token with custom claims")
        void customClaims() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("admin")
                    .claim("role", "administrator")
                    .claim("level", 5)
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build();

            Map<String, Object> result = validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET);
            assertEquals("admin", result.get("sub"));
            assertEquals("administrator", result.get("role"));
        }

        @Test
        @DisplayName("token with issuer and audience validated")
        void issuerAndAudience() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user-1")
                    .issuer("auth-service")
                    .audience("my-api")
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build();

            Map<String, Object> result = validator.validateHmac(
                    buildHmacJwt(claims), HMAC_SECRET, "auth-service", "my-api");
            assertEquals("user-1", result.get("sub"));
        }

        @Test
        @DisplayName("exp claim converted to epoch seconds")
        void expConvertedToEpochSeconds() throws Exception {
            long futureMillis = System.currentTimeMillis() + 60_000;
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .expirationTime(new Date(futureMillis))
                    .build();

            Map<String, Object> result = validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET);
            Object exp = result.get("exp");
            assertInstanceOf(Long.class, exp);
        }

        @Test
        @DisplayName("token without exp still validates")
        void noExpiration() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("service-account")
                    .build();

            Map<String, Object> result = validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET);
            assertEquals("service-account", result.get("sub"));
        }
    }

    // =========================================================================
    //  HMAC Validation — Failure Cases
    // =========================================================================

    @Nested
    @DisplayName("HMAC — invalid tokens")
    class HmacInvalid {

        @Test
        @DisplayName("wrong secret → INVALID_SIGNATURE")
        void wrongSecret() throws Exception {
            String other = "another-very-long-secret-key-for-testing-purposes!!";
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("x").build();
            String token = buildHmacJwt(claims);

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac(token, other));
            assertEquals(Reason.INVALID_SIGNATURE, ex.getReason());
        }

        @Test
        @DisplayName("expired token → EXPIRED")
        void expiredToken() throws Exception {
            JwtValidator strict = new JwtValidator(0);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .expirationTime(new Date(System.currentTimeMillis() - 10_000))
                    .build();

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> strict.validateHmac(buildHmacJwt(claims), HMAC_SECRET));
            assertEquals(Reason.EXPIRED, ex.getReason());
        }

        @Test
        @DisplayName("not-yet-valid token → NOT_YET_VALID")
        void notYetValid() throws Exception {
            JwtValidator strict = new JwtValidator(0);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .notBeforeTime(new Date(System.currentTimeMillis() + 300_000))
                    .build();

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> strict.validateHmac(buildHmacJwt(claims), HMAC_SECRET));
            assertEquals(Reason.NOT_YET_VALID, ex.getReason());
        }

        @Test
        @DisplayName("wrong issuer → INVALID_ISSUER")
        void wrongIssuer() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .issuer("wrong-service")
                    .build();

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac(
                            buildHmacJwt(claims), HMAC_SECRET, "expected-service", null));
            assertEquals(Reason.INVALID_ISSUER, ex.getReason());
        }

        @Test
        @DisplayName("wrong audience → INVALID_AUDIENCE")
        void wrongAudience() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .audience("wrong-api")
                    .build();

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac(
                            buildHmacJwt(claims), HMAC_SECRET, null, "expected-api"));
            assertEquals(Reason.INVALID_AUDIENCE, ex.getReason());
        }

        @Test
        @DisplayName("malformed token → MALFORMED_TOKEN")
        void malformedToken() {
            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac("not.a.jwt", HMAC_SECRET));
            assertEquals(Reason.MALFORMED_TOKEN, ex.getReason());
        }

        @Test
        @DisplayName("garbage string → MALFORMED_TOKEN")
        void garbageString() {
            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac("totalgarbage", HMAC_SECRET));
            assertEquals(Reason.MALFORMED_TOKEN, ex.getReason());
        }

        @Test
        @DisplayName("null token → IllegalArgumentException")
        void nullToken() {
            assertThrows(IllegalArgumentException.class,
                    () -> validator.validateHmac(null, HMAC_SECRET));
        }

        @Test
        @DisplayName("null secret → IllegalArgumentException")
        void nullSecret() throws Exception {
            String token = buildHmacJwt(new JWTClaimsSet.Builder().subject("x").build());
            assertThrows(IllegalArgumentException.class,
                    () -> validator.validateHmac(token, null));
        }

        @Test
        @DisplayName("empty token → IllegalArgumentException")
        void emptyToken() {
            assertThrows(IllegalArgumentException.class,
                    () -> validator.validateHmac("", HMAC_SECRET));
        }
    }

    // =========================================================================
    //  RSA Validation
    // =========================================================================

    @Nested
    @DisplayName("RSA validation")
    class RsaTests {

        @Test
        @DisplayName("valid RSA-signed token")
        void validRsa() throws Exception {
            KeyPair kp = generateRsaKeyPair();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("rsa-user")
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build();

            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(kp.getPrivate()));
            String token = jwt.serialize();

            String pem = publicKeyToPem((RSAPublicKey) kp.getPublic());
            Map<String, Object> result = validator.validateRsa(token, pem);
            assertEquals("rsa-user", result.get("sub"));
        }

        @Test
        @DisplayName("wrong RSA key → INVALID_SIGNATURE")
        void wrongRsaKey() throws Exception {
            KeyPair signingKp = generateRsaKeyPair();
            KeyPair otherKp = generateRsaKeyPair();

            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user").build();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(signingKp.getPrivate()));
            String token = jwt.serialize();

            String wrongPem = publicKeyToPem((RSAPublicKey) otherKp.getPublic());
            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateRsa(token, wrongPem));
            assertEquals(Reason.INVALID_SIGNATURE, ex.getReason());
        }

        @Test
        @DisplayName("HMAC token passed to RSA validator → UNSUPPORTED_ALGORITHM")
        void hmacToRsa() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user").build();
            String hmacToken = buildHmacJwt(claims);
            KeyPair kp = generateRsaKeyPair();
            String pem = publicKeyToPem((RSAPublicKey) kp.getPublic());

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateRsa(hmacToken, pem));
            assertEquals(Reason.UNSUPPORTED_ALGORITHM, ex.getReason());
        }

        @Test
        @DisplayName("invalid PEM key → INVALID_KEY")
        void invalidPem() throws Exception {
            KeyPair kp = generateRsaKeyPair();
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user").build();
            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(kp.getPrivate()));

            JwtValidationException ex = assertThrows(JwtValidationException.class,
                    () -> validator.validateRsa(jwt.serialize(), "not-a-valid-pem-key"));
            assertEquals(Reason.INVALID_KEY, ex.getReason());
        }

        @Test
        @DisplayName("RSA with issuer and audience constraints")
        void rsaWithConstraints() throws Exception {
            KeyPair kp = generateRsaKeyPair();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .issuer("auth-svc")
                    .audience("web-app")
                    .expirationTime(new Date(System.currentTimeMillis() + 60_000))
                    .build();

            SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
            jwt.sign(new RSASSASigner(kp.getPrivate()));
            String pem = publicKeyToPem((RSAPublicKey) kp.getPublic());

            Map<String, Object> result = validator.validateRsa(
                    jwt.serialize(), pem, "auth-svc", "web-app");
            assertEquals("user", result.get("sub"));
        }
    }

    // =========================================================================
    //  Clock Skew
    // =========================================================================

    @Nested
    @DisplayName("Clock skew tolerance")
    class ClockSkewTests {

        @Test
        @DisplayName("recently expired token accepted with default 60s skew")
        void recentlyExpiredAccepted() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .expirationTime(new Date(System.currentTimeMillis() - 30_000))
                    .build();

            Map<String, Object> result = validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET);
            assertEquals("user", result.get("sub"));
        }

        @Test
        @DisplayName("long-expired token rejected even with default skew")
        void longExpiredRejected() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("user")
                    .expirationTime(new Date(System.currentTimeMillis() - 120_000))
                    .build();

            assertThrows(JwtValidationException.class,
                    () -> validator.validateHmac(buildHmacJwt(claims), HMAC_SECRET));
        }
    }
}
