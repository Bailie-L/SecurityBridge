package com.securitybridge.bridge;

import py4j.GatewayServer;

import java.util.UUID;
import java.util.logging.Logger;
import java.util.logging.Level;

import com.securitybridge.SecurityManager;

/**
 * Py4J Gateway Server exposing Java security components to Python.
 *
 * <p>Acts as the entry point for the Py4J bridge. Starts a
 * {@link GatewayServer} on port 25333 with token-based authentication
 * read from the {@code SECURITYBRIDGE_AUTH_TOKEN} environment variable.</p>
 *
 * <h3>Authentication</h3>
 * If the environment variable is not set, a random UUID token is generated
 * and written to stdout (for development only). In production, always set
 * the environment variable so both the gateway and the Python client share
 * the same token.
 *
 * <h3>Shutdown</h3>
 * A JVM shutdown hook is registered to call {@link GatewayServer#shutdown()}
 * on SIGTERM / SIGINT, ensuring clean socket teardown.
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * export SECURITYBRIDGE_AUTH_TOKEN=my-secret
 * java -cp "build/classes/java/main:libs/py4j-0.10.9.9.jar" \
 *     com.securitybridge.bridge.SecurityGatewayServer
 * }</pre>
 */
public class SecurityGatewayServer {

    private static final Logger LOGGER = Logger.getLogger(SecurityGatewayServer.class.getName());

    private static final int GATEWAY_PORT = 25333;

    private final SecurityManager securityManager;

    public SecurityGatewayServer() {
        this.securityManager = SecurityManager.getInstance();
        LOGGER.info("SecurityGatewayServer initialised");
    }

    /**
     * Returns the singleton {@link SecurityManager} instance.
     * Called by Py4J when the Python client accesses the entry point.
     *
     * @return the security manager
     */
    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    /**
     * Health-check method — always returns {@code true} while the JVM is up.
     *
     * @return {@code true}
     */
    public boolean isAlive() {
        return true;
    }

    // =========================================================================
    //  Main
    // =========================================================================

    public static void main(String[] args) {
        try {
            SecurityGatewayServer entryPoint = new SecurityGatewayServer();

            String authToken = resolveAuthToken();

            GatewayServer server = new GatewayServer.GatewayServerBuilder(entryPoint)
                    .authToken(authToken)
                    .javaPort(GATEWAY_PORT)
                    .build();

            // Register shutdown hook for clean teardown on SIGTERM / SIGINT
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                LOGGER.info("Shutdown hook triggered — stopping gateway");
                server.shutdown();
            }));

            server.start();
            LOGGER.info("Gateway listening on port " + server.getListeningPort());
            LOGGER.info("Press Ctrl+C to stop");

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to start gateway", e);
            System.exit(1);
        }
    }

    /**
     * Resolves the auth token from the environment, or generates a
     * random one for development use.
     */
    private static String resolveAuthToken() {
        String token = System.getenv("SECURITYBRIDGE_AUTH_TOKEN");

        if (token != null && !token.isEmpty()) {
            LOGGER.info("Using auth token from SECURITYBRIDGE_AUTH_TOKEN env var");
            return token;
        }

        token = UUID.randomUUID().toString();
        LOGGER.warning(
                "SECURITYBRIDGE_AUTH_TOKEN not set — generated dev token. "
                + "Set the env var for production use."
        );
        // Print to stdout so the Python launcher can capture it if needed
        System.out.println("GENERATED_AUTH_TOKEN=" + token);
        return token;
    }
}
