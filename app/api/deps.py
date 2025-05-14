from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from typing import Generator, Optional, Any

from app.core.config import settings
from app.api.v1.schemas import TokenPayload
from app.services.aws_scanner import AwsScanner
from app.services.security_analyzer import SecurityAnalyzer
from app.db.session import SessionLocal

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/token")

# For MVP, we'll use a simple placeholder function for current user
# In a real implementation, this would validate the token and get the user from a database
def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """
    Validate access token and return current user.
    For MVP, we'll use a simplified approach.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    
    # For MVP, we'll just return the sub field as the user ID
    # In a real implementation, we would look up the user in a database
    user_id = token_data.sub
    if user_id is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user_id

# Database session dependency
def get_db() -> Generator:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Service dependencies
def get_aws_scanner() -> AwsScanner:
    """Provide AwsScanner instance."""
    return AwsScanner()

def get_security_analyzer() -> SecurityAnalyzer:
    """Provide SecurityAnalyzer instance."""
    return SecurityAnalyzer()

# Placeholder for graph database dependency (Phase 2)
async def get_graph_db() -> Optional[Any]: # Changed to async to match usage
    """Placeholder for graph database dependency."""
    # In a real scenario, this would establish and return a graph database connection/client
    # For example: from app.services.graph.connection import GraphDatabase
    # graph_db_client = GraphDatabase(uri=settings.NEO4J_URI, user=settings.NEO4J_USER, password=settings.NEO4J_PASSWORD)
    # yield graph_db_client # If it needs to be a generator like get_db
    # await graph_db_client.connect() # If it has an async connect method
    return None # For MVP, returning None as graph features are not yet integrated
