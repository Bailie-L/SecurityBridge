#!/usr/bin/env python
"""
SecurityBridge — Java Gateway Launcher.

Starts the Java SecurityGatewayServer as a background process and optionally
keeps the terminal attached for interactive use.

Usage:
    python start_security_bridge.py            # Start detached
    python start_security_bridge.py --wait     # Start and keep attached (Ctrl+C to stop)

Environment:
    SECURITYBRIDGE_AUTH_TOKEN  Shared secret for Py4J gateway auth (required).
"""

import os
import sys
import subprocess
import time
import logging
import atexit

# --- Project paths ------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
LOG_FILE = os.path.join(LOGS_DIR, "security_bridge.log")

# --- Logging ------------------------------------------------------------------

os.makedirs(LOGS_DIR, exist_ok=True)

_file_handler = logging.FileHandler(LOG_FILE)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), _file_handler],
)
logger = logging.getLogger("SecurityBridgeStarter")

atexit.register(_file_handler.close)

# --- Constants ----------------------------------------------------------------

CLASSES_DIR = os.path.join(PROJECT_ROOT, "build/classes/java/main")
PY4J_JAR = os.path.join(PROJECT_ROOT, "libs/py4j-0.10.9.9.jar")
GATEWAY_CLASS = "com.securitybridge.bridge.SecurityGatewayServer"
DEFAULT_STARTUP_WAIT = 2  # seconds


# ==============================================================================
#  Bridge Lifecycle
# ==============================================================================

def start_bridge(wait_seconds=DEFAULT_STARTUP_WAIT):
    """
    Start the Java gateway server as a subprocess.

    The ``SECURITYBRIDGE_AUTH_TOKEN`` environment variable is forwarded to
    the child process so the gateway can enforce authenticated connections.

    Args:
        wait_seconds: Seconds to wait for the JVM to initialise.

    Returns:
        subprocess.Popen on success, None on failure.
    """
    if not os.path.isdir(CLASSES_DIR):
        logger.error(f"Java classes not found: {CLASSES_DIR}")
        logger.error("Run './gradlew compileJava' first.")
        return None

    if not os.path.isfile(PY4J_JAR):
        logger.error(f"Py4J JAR not found: {PY4J_JAR}")
        return None

    sep = ";" if sys.platform.startswith("win") else ":"
    classpath = f"{CLASSES_DIR}{sep}{PY4J_JAR}"

    command = ["java", "-cp", classpath, GATEWAY_CLASS]
    logger.info(f"Starting gateway: {' '.join(command)}")

    # Forward the full environment including the auth token
    env = {**os.environ}
    auth_token = env.get("SECURITYBRIDGE_AUTH_TOKEN")
    if not auth_token:
        logger.warning(
            "SECURITYBRIDGE_AUTH_TOKEN is not set — "
            "the gateway will auto-generate a token (dev only)"
        )

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
        )

        time.sleep(wait_seconds)

        if process.poll() is not None:
            _, stderr = process.communicate()
            logger.error(f"Gateway failed to start: {stderr}")
            return None

        logger.info("Java gateway started successfully (PID %d)", process.pid)
        return process

    except FileNotFoundError:
        logger.error("'java' command not found — is JDK 17+ installed and on PATH?")
        return None
    except Exception as e:
        logger.error(f"Error starting gateway: {e}")
        return None


def stop_bridge(process):
    """
    Gracefully terminate a gateway process (SIGTERM → SIGKILL fallback).

    Args:
        process: The Popen object returned by start_bridge().

    Returns:
        True if stopped, False otherwise.
    """
    if process is None or process.poll() is not None:
        return True

    logger.info("Stopping Java gateway (PID %d)...", process.pid)
    try:
        process.terminate()
        process.wait(timeout=5)
        logger.info("Gateway stopped gracefully")
        return True
    except subprocess.TimeoutExpired:
        logger.warning("Gateway did not terminate, sending SIGKILL")
        process.kill()
        process.wait()
        logger.info("Gateway killed")
        return True
    except Exception as e:
        logger.error(f"Error stopping gateway: {e}")
        return False


def is_bridge_running():
    """
    Check if a Java gateway is reachable by attempting a Py4J connection.

    Returns:
        True if the bridge responds, False otherwise.
    """
    try:
        from security_bridge import SecurityBridge
        bridge = SecurityBridge()
        return bridge.java_available
    except Exception:
        return False


# ==============================================================================
#  Main
# ==============================================================================

def main(argv=None):
    """
    Entry point.

    Args:
        argv: Command-line arguments (defaults to sys.argv).

    Returns:
        Exit code: 0 on success, 1 on failure.
    """
    if argv is None:
        argv = sys.argv

    if is_bridge_running():
        logger.info("Java gateway is already running")
        return 0

    process = start_bridge()
    if process is None:
        logger.error("Failed to start Java gateway")
        return 1

    if "--wait" in argv:
        # Attach mode — keep running until Ctrl+C
        atexit.register(stop_bridge, process)
        logger.info("Gateway running. Press Ctrl+C to stop.")
        try:
            while process.poll() is None:
                time.sleep(1)
            # Process exited on its own
            _, stderr = process.communicate()
            logger.error(f"Gateway exited unexpectedly: {stderr}")
            return 1
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            stop_bridge(process)
    else:
        # Detached mode — exit and leave the gateway running
        logger.info(
            "Gateway running in background (PID %d). "
            "Use --wait to keep this terminal attached.",
            process.pid,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
