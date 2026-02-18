"""
SecurityBridge FastAPI Demo Application

Demonstrates JWT validation, HTML sanitization, and input validation
through the SecurityBridge Python-to-Java security bridge.
"""

import sys
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Add SecurityBridge Python source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'python'))
from security import get_instance

# --- Pydantic Models ---

class JwtVerifyRequest(BaseModel):
    token: str = Field(..., description="JWT token to validate")
    secret: str = Field(..., description="HMAC secret or RSA public key PEM")
    algorithm: str = Field(default="hmac", description="'hmac' or 'rsa'")
    expected_issuer: Optional[str] = Field(default=None, description="Expected issuer claim")
    expected_audience: Optional[str] = Field(default=None, description="Expected audience claim")

class SanitizeRequest(BaseModel):
    html: str = Field(..., description="Untrusted HTML input to sanitize")
    policy: str = Field(default="STRICT", description="Sanitization policy: STRICT, BASIC, or RICH")

class ValidateRequest(BaseModel):
    value: str = Field(..., description="Input string to validate")
    param_name: str = Field(default="input", description="Parameter name for error messages")
    validation_type: str = Field(default="default", description="Validation type: alphanumeric, path, or default")

class RangeValidateRequest(BaseModel):
    value: float = Field(..., description="Numeric value to validate")
    min_value: float = Field(..., description="Minimum allowed value")
    max_value: float = Field(..., description="Maximum allowed value")
    param_name: str = Field(default="value", description="Parameter name for error messages")

class ProtectedRequest(BaseModel):
    data: str = Field(..., description="Payload for protected endpoint")

# --- App Setup ---

app = FastAPI(
    title="SecurityBridge Demo",
    description=(
        "Demonstrates JWT validation, HTML sanitization, and input validation "
        "through the SecurityBridge Python-to-Java security bridge."
    ),
    version="1.0.0",
)

def get_security():
    """Dependency that provides the SecurityBridge singleton."""
    return get_instance()


# --- Health Check ---

@app.get("/health", tags=["System"])
def health_check(sec=Depends(get_security)):
    """Check bridge status and Java availability."""
    bridge = sec.bridge
    java_available = bridge.java_available if bridge else False
    return {
        "status": "healthy",
        "java_available": java_available,
        "bridge_connected": bridge is not None,
        "fallback_mode": not java_available,
    }


# --- JWT Endpoints ---

@app.post("/auth/verify", tags=["JWT"])
def verify_jwt(req: JwtVerifyRequest, sec=Depends(get_security)):
    """
    Validate a JWT token and return its claims.

    Supports HMAC (HS256/384/512) and RSA (RS256/384/512) algorithms.
    """
    try:
        if req.algorithm.lower() == "rsa":
            claims = sec.validate_jwt_rsa(req.token, req.secret)
        elif req.expected_issuer or req.expected_audience:
            claims = sec.validate_jwt(
                req.token, req.secret,
                expected_issuer=req.expected_issuer,
                expected_audience=req.expected_audience,
            )
        else:
            claims = sec.validate_jwt(req.token, req.secret)

        return {"valid": True, "claims": claims}

    except ValueError as e:
        # Malformed token or unsupported algorithm → 400
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        # Invalid signature, expired, not-yet-valid, wrong issuer/audience → 401
        raise HTTPException(status_code=401, detail=str(e))
    except RuntimeError as e:
        # Invalid key or security disabled → 500
        raise HTTPException(status_code=500, detail=str(e))


# --- JWT Middleware for Protected Routes ---

async def require_jwt(request: Request, sec=Depends(get_security)):
    """
    Dependency that extracts and validates a JWT from the Authorization header.
    Injects validated claims into request.state.claims.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header[len("Bearer "):]

    jwt_secret = os.environ.get("DEMO_JWT_SECRET")
    if not jwt_secret:
        raise HTTPException(status_code=500, detail="DEMO_JWT_SECRET not configured")

    try:
        claims = sec.validate_jwt(token, jwt_secret)
        request.state.claims = claims
        return claims
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/protected", tags=["JWT"], dependencies=[Depends(require_jwt)])
def protected_endpoint(req: ProtectedRequest, request: Request):
    """
    Example protected endpoint. Requires a valid JWT in the Authorization header.
    Returns the validated claims alongside the request data.
    """
    return {
        "message": "Access granted",
        "claims": request.state.claims,
        "your_data": req.data,
    }


# --- HTML Sanitization Endpoints ---

@app.post("/sanitize", tags=["HTML Sanitization"])
def sanitize_html(req: SanitizeRequest, sec=Depends(get_security)):
    """
    Sanitize HTML input using the specified policy.

    Policies:
    - **STRICT**: Strips all HTML tags, returns plain text
    - **BASIC**: Allows formatting tags (bold, italic, lists)
    - **RICH**: Allows formatting + links, images, tables, headings
    """
    try:
        sanitized = sec.sanitize_html(req.html, req.policy)
        was_modified = sanitized != req.html
        return {
            "sanitized": sanitized,
            "original_length": len(req.html),
            "sanitized_length": len(sanitized),
            "was_modified": was_modified,
            "policy": req.policy.upper(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Input Validation Endpoints ---

@app.post("/validate", tags=["Input Validation"])
def validate_string(req: ValidateRequest, sec=Depends(get_security)):
    """
    Validate a string input.

    Types:
    - **alphanumeric**: Letters, digits, underscores only
    - **path**: Safe file path characters (no directory traversal)
    - **default**: Non-empty string
    """
    try:
        result = sec.validate_string(req.value, req.param_name, req.validation_type)
        return {
            "valid": True,
            "value": result,
            "validation_type": req.validation_type,
        }
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/validate/range", tags=["Input Validation"])
def validate_range(req: RangeValidateRequest, sec=Depends(get_security)):
    """Validate that a numeric value falls within the specified range."""
    try:
        result = sec.validate_range(req.value, req.min_value, req.max_value, req.param_name)
        return {
            "valid": True,
            "value": result,
            "min": req.min_value,
            "max": req.max_value,
        }
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Error Handlers ---

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all for unhandled exceptions."""
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal server error: {type(exc).__name__}"},
    )


# --- Entry Point ---

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
