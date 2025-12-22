"""
FastAPI integration for Tenuo.

Provides a dependency for extracting and validating warrants from headers.
"""

from typing import Optional, Any
import base64

# Use string forward refs or try import, FastAPI must be installed
try:
    from fastapi import Header, HTTPException, Depends, Request, status
    from fastapi.security import APIKeyHeader
except ImportError:
    # Allow import for type checking if needed, but raise at runtime use
    Header = Any  # type: ignore
    HTTPException = Any # type: ignore
    Depends = Any # type: ignore
    Request = Any # type: ignore
    status = Any # type: ignore
    APIKeyHeader = Any # type: ignore


from tenuo_core import Warrant  # type: ignore[import-untyped]



# Define standard headers
X_TENUO_WARRANT = "X-Tenuo-Warrant"
X_TENUO_POP = "X-Tenuo-PoP"

# Reusable security scheme for Swagger UI
api_key_header = APIKeyHeader(name=X_TENUO_WARRANT, auto_error=False)


def get_warrant_header(
    x_tenuo_warrant: Optional[str] = Header(None, alias=X_TENUO_WARRANT)
) -> Optional[Warrant]:
    """
    FastAPI dependency to extract and parse the X-Tenuo-Warrant header.
    Returns None if missing. Raises HTTPException on invalid format.
    """
    if not x_tenuo_warrant:
        return None
        
    try:
        return Warrant.from_base64(x_tenuo_warrant)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid X-Tenuo-Warrant header: {str(e)}"
        )


def require_warrant(
    request: Request,
    warrant: Optional[Warrant] = Depends(get_warrant_header),
    x_tenuo_pop: Optional[str] = Header(None, alias=X_TENUO_POP),
) -> Warrant:
    """
    FastAPI dependency that REQUIRES a valid warrant and PoP signature.
    Use this to protect routes.
    
    This dependency:
    1. Parses X-Tenuo-Warrant
    2. Parses X-Tenuo-PoP
    3. Verifies the signature against the request
    4. Returns the verified Warrant object
    
    Warning: This implementation currently only validates presence of headers.
    Full verification logic (checking tool, args, sig) requires integration
    into the route handler or a more complex dependency factory.
    
    Usage:
        @app.get("/items")
        def read_items(warrant: Warrant = Depends(require_warrant)):
            ...
    """
    if not warrant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Tenuo-Warrant header"
        )
        
    if not x_tenuo_pop:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Tenuo-PoP header"
        )
        
    # TODO: Perform full authorization check here?
    # To fully verify, we need the route info (tool name) and args.
    # FastAPI doesn't easily expose "current tool name" in a dependency without
    # middleware or custom routing.
    # For now, we return the parsed warrant and user must authorize() manually
    # or use a decorator/wrapper.
    
    return warrant


class TenuoSecurity:
    """
    Helper for FastAPI security.
    """
    
    def __init__(self, tool: str):
        self.tool = tool
        
    def __call__(
        self,
        request: Request,
        warrant: Optional[Warrant] = Depends(get_warrant_header),
        x_tenuo_pop: Optional[str] = Header(None, alias=X_TENUO_POP),
    ) -> Warrant:
        """
        Dependency that verifies authorization for a SPECIFIC tool.
        
        Usage:
            @app.get("/search")
            def search(warrant: Warrant = Depends(TenuoSecurity("search"))):
                ...
        """
        # 1. Check Headers
        if not warrant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Tenuo-Warrant header"
            )
        if not x_tenuo_pop:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Tenuo-PoP header"
            )
            
        # 2. Extract Args (Simplified)
        # In a real app, this should match exactly what is signed.
        # For query params:
        query_params = dict(request.query_params)
        # For body, we'd need to await request.json(), but we can't consume the stream
        # in a dependency easily without caching middleware.
        # Limitation: This dependency currently only validates query params for PoP.
        
        # 3. Decode PoP Sig
        try:
            pop_sig_bytes = base64.b64decode(x_tenuo_pop)
        except Exception:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid base64 in X-Tenuo-PoP"
            )

        # 4. Authorize
        # Note: If no query params and body is used, this check might fail or be incomplete
        # depending on how the client signed it.
        # Assuming query params + path params for now.
        auth_args = {**request.path_params, **query_params}
        
        if not warrant.authorize(self.tool, auth_args, pop_sig_bytes):
             raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Authorization denied for tool '{self.tool}'"
            )
            
        return warrant
