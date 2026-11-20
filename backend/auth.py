"""
Authentication and authorization helpers for dashboard endpoints.
"""
from typing import Optional
from fastapi import Header, HTTPException, Query, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from backend.database import get_tenant_for_token

security = HTTPBearer(auto_error=False)


def extract_token(
    authorization_header: Optional[str] = None,
    x_api_key_header: Optional[str] = None,
) -> Optional[str]:
    """Extract raw token string from Bearer authorization or X-API-Key header."""
    if authorization_header:
        parts = authorization_header.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
        return authorization_header.strip()
    if x_api_key_header:
        return x_api_key_header.strip()
    return None


async def require_tenant_auth(
    tenant_id: str = Query(..., min_length=1, description="Tenant ID to access"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """
    Ensure the client provides a registered API token and that the token
    is authorized specifically for the requested tenant_id.
    """
    token = extract_token(authorization, x_api_key)
    if not token:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "API token required in Authorization or X-API-Key header"},
        )

    authorized_tenant = await get_tenant_for_token(token)
    if not authorized_tenant:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "message": "Invalid API token"},
        )

    if authorized_tenant != tenant_id:
        raise HTTPException(
            status_code=403,
            detail={"error": "forbidden", "message": "Token is not authorized to access the requested tenant"},
        )

    return tenant_id
