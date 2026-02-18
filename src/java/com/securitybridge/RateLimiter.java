package com.securitybridge;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.logging.Level;

/**
 * General-purpose rate limiter with suspicious client detection.
 *
 * <p>Provides per-client, per-operation rate limiting using a sliding window
 * algorithm (circular timestamp buffer). Clients exceeding a configurable
 * failure threshold are temporarily flagged as suspicious.</p>
 *
 * <h3>Thread Safety</h3>
 * All public methods are thread-safe. Internal maps are wrapped via
 * {@link Collections#synchronizedMap} with LRU eviction at 10,000 entries
 * to prevent memory exhaustion under sustained load.
 *
 * <h3>Usage Example</h3>
 * <pre>{@code
 * RateLimiter limiter = RateLimiter.getInstance();
 *
 * // Check if a request is allowed
 * if (!limiter.checkRateLimit("client-192.168.1.1", "POST /auth/verify")) {
 *     // reject - rate limit exceeded
 * }
 *
 * // Record a failure (e.g. bad JWT, malformed input)
 * limiter.recordFailure("client-192.168.1.1", "Invalid JWT signature");
 *
 * // Query suspicious status
 * if (limiter.isSuspicious("client-192.168.1.1")) {
 *     // apply stricter validation or block
 * }
 * }</pre>
 */
public class RateLimiter {

    private static final Logger LOGGER = Logger.getLogger(RateLimiter.class.getName());

    private static volatile RateLimiter instance;

    /** Default maximum operations per second per client+operation key. */
    private static final int DEFAULT_RATE_LIMIT = 20;

    /** Number of recorded failures before a client is flagged suspicious. */
    private static final int SUSPICIOUS_THRESHOLD = 5;

    /** Duration (ms) a client remains flagged as suspicious. */
    private static final long SUSPICIOUS_DURATION_MS = 60_000;

    /** Maximum tracked keys per map (LRU eviction beyond this). */
    private static final int MAX_MAP_ENTRIES = 10_000;

    // --- Internal state (all maps are synchronized + LRU-bounded) ---

    private final Map<String, SlidingWindow> rateLimits;
    private final Map<String, AtomicInteger> failureCounts;
    private final Map<String, Long> suspiciousUntil;

    /**
     * Private constructor - use {@link #getInstance()}.
     */
    private RateLimiter() {
        this.rateLimits = Collections.synchronizedMap(boundedLruMap(MAX_MAP_ENTRIES));
        this.failureCounts = Collections.synchronizedMap(boundedLruMap(MAX_MAP_ENTRIES));
        this.suspiciousUntil = Collections.synchronizedMap(boundedLruMap(MAX_MAP_ENTRIES));
        LOGGER.info("RateLimiter initialized (limit=" + DEFAULT_RATE_LIMIT
                + "/s, suspiciousThreshold=" + SUSPICIOUS_THRESHOLD + ")");
    }

    /**
     * Returns the singleton instance (double-checked locking).
     *
     * @return the RateLimiter singleton
     */
    public static RateLimiter getInstance() {
        if (instance == null) {
            synchronized (RateLimiter.class) {
                if (instance == null) {
                    instance = new RateLimiter();
                }
            }
        }
        return instance;
    }

    // =========================================================================
    //  Rate Limiting
    // =========================================================================

    /**
     * Checks whether a request from {@code clientId} for {@code operation}
     * is within the default rate limit.
     *
     * @param clientId  non-empty client identifier (e.g. IP, session ID)
     * @param operation non-empty operation name (e.g. "POST /auth/verify")
     * @return {@code true} if the request is allowed, {@code false} if rate-limited
     * @throws IllegalArgumentException if either argument is null or empty
     */
    public boolean checkRateLimit(String clientId, String operation) {
        ValidationUtils.requireNonEmpty(clientId, "clientId");
        ValidationUtils.requireNonEmpty(operation, "operation");

        String key = clientId + ":" + operation;

        SlidingWindow window;
        synchronized (rateLimits) {
            window = rateLimits.computeIfAbsent(key, k -> new SlidingWindow(DEFAULT_RATE_LIMIT));
        }

        boolean allowed = window.tryAcquire();
        if (!allowed) {
            LOGGER.fine("Rate limit exceeded: " + key);
        }
        return allowed;
    }

    /**
     * Sets a custom rate limit for a specific client and operation.
     *
     * @param clientId        non-empty client identifier
     * @param operation       non-empty operation name
     * @param requestsPerSec  maximum requests per second (1-1000)
     * @throws IllegalArgumentException if arguments are invalid
     */
    public void setRateLimit(String clientId, String operation, int requestsPerSec) {
        ValidationUtils.requireNonEmpty(clientId, "clientId");
        ValidationUtils.requireNonEmpty(operation, "operation");
        ValidationUtils.requireRange(requestsPerSec, 1, 1000, "requestsPerSec");

        String key = clientId + ":" + operation;
        rateLimits.put(key, new SlidingWindow(requestsPerSec));
    }

    // =========================================================================
    //  Failure Tracking & Suspicious Client Detection
    // =========================================================================

    /**
     * Records a validation or security failure for a client.
     *
     * <p>When the failure count reaches {@link #SUSPICIOUS_THRESHOLD}, the
     * client is flagged as suspicious for {@link #SUSPICIOUS_DURATION_MS} ms
     * and a security event is recorded via {@link SecurityManager}.</p>
     *
     * @param clientId non-empty client identifier
     * @param reason   human-readable failure reason (for logging)
     * @throws IllegalArgumentException if clientId is null or empty
     */
    public void recordFailure(String clientId, String reason) {
        ValidationUtils.requireNonEmpty(clientId, "clientId");

        LOGGER.warning("Validation failure [" + clientId + "]: " + reason);

        AtomicInteger count;
        synchronized (failureCounts) {
            count = failureCounts.computeIfAbsent(clientId, k -> new AtomicInteger(0));
        }
        int total = count.incrementAndGet();

        if (total >= SUSPICIOUS_THRESHOLD && !isSuspicious(clientId)) {
            long until = System.currentTimeMillis() + SUSPICIOUS_DURATION_MS;
            suspiciousUntil.put(clientId, until);
            LOGGER.warning("Client flagged suspicious: " + clientId
                    + " (failures=" + total + ")");

            SecurityManager.getInstance().recordSecurityEvent(
                    "failure_threshold_exceeded",
                    "Client: " + clientId + ", Failures: " + total,
                    Level.WARNING
            );
        }
    }

    /**
     * Returns whether a client is currently flagged as suspicious.
     *
     * <p>Expired flags are lazily cleared on access.</p>
     *
     * @param clientId non-empty client identifier
     * @return {@code true} if the client is currently suspicious
     */
    public boolean isSuspicious(String clientId) {
        ValidationUtils.requireNonEmpty(clientId, "clientId");

        Long until = suspiciousUntil.get(clientId);
        if (until == null) {
            return false;
        }
        if (System.currentTimeMillis() >= until) {
            suspiciousUntil.remove(clientId);
            failureCounts.remove(clientId);
            return false;
        }
        return true;
    }

    /**
     * Clears all rate-limit and failure tracking data for a client.
     *
     * @param clientId non-empty client identifier
     */
    public void clearClient(String clientId) {
        ValidationUtils.requireNonEmpty(clientId, "clientId");

        synchronized (rateLimits) {
            rateLimits.entrySet().removeIf(e -> e.getKey().startsWith(clientId + ":"));
        }
        failureCounts.remove(clientId);
        suspiciousUntil.remove(clientId);
    }

    /**
     * Resets the singleton instance. <strong>Testing only.</strong>
     */
    static synchronized void resetInstance() {
        instance = null;
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    /**
     * Creates a bounded LinkedHashMap with LRU eviction.
     */
    private static <K, V> LinkedHashMap<K, V> boundedLruMap(int maxEntries) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return size() > maxEntries;
            }
        };
    }

    // =========================================================================
    //  Sliding Window Rate Limiter
    // =========================================================================

    /**
     * Sliding-window rate limiter using a circular timestamp buffer.
     *
     * <p>Tracks the last N request timestamps (where N = max requests/sec).
     * A new request is allowed only if the oldest tracked timestamp is more
     * than 1 second ago.</p>
     */
    private static class SlidingWindow {
        private final int maxPerSecond;
        private final long[] timestamps;
        private int cursor;

        SlidingWindow(int maxPerSecond) {
            this.maxPerSecond = maxPerSecond;
            this.timestamps = new long[maxPerSecond];
            this.cursor = 0;
        }

        /**
         * Attempts to acquire a permit.
         *
         * @return {@code true} if the request is within the rate limit
         */
        synchronized boolean tryAcquire() {
            long now = System.currentTimeMillis();
            long windowStart = now - 1_000;

            if (timestamps[cursor] > windowStart) {
                return false;
            }

            timestamps[cursor] = now;
            cursor = (cursor + 1) % maxPerSecond;
            return true;
        }
    }
}
