from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.api.v1.schemas import Token, UserCreate

router = APIRouter()

# For MVP, we'll use a simple in-memory store for users
# In a real implementation, this would be a database
USERS = {}

@router.post("/register", response_model=Token)
async def register_user(user_in: UserCreate) -> Any:
    """
    Register a new user.
    
    For MVP, we'll use a simple in-memory store.
    In a real implementation, this would create a user in a database.
    """
    if user_in.email in USERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )
    
    hashed_password = get_password_hash(user_in.password)
    USERS[user_in.email] = {
        "email": user_in.email,
        "hashed_password": hashed_password,
        "id": user_in.email,  # For MVP, use email as ID
    }
    
    # Create access token for the new user
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user_in.email, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    """
    OAuth2 compatible token login.
    
    For MVP, we'll use a simple in-memory authentication.
    In a real implementation, this would validate against a database.
    """
    user = USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        subject=user["id"], expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.post("/verify-aws-credentials")
async def verify_aws_credentials(
    credentials: dict,
) -> Any:
    """
    Verify AWS credentials.
    
    For MVP, we'll delegate to AWS SDK validation logic.
    In a real implementation, this would verify credentials with AWS.
    """
    from app.providers.aws_provider import AwsProvider
    
    try:
        # Create AWS provider with provided credentials
        aws_provider = AwsProvider(
            profile_name=credentials.get("profile_name"),
            access_key_id=credentials.get("access_key_id"),
            secret_access_key=credentials.get("secret_access_key"),
            session_token=credentials.get("session_token"),
            region=credentials.get("region", "us-east-1"),
        )
        
        # Validate credentials
        valid = aws_provider.validate_credentials()
        
        if not valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid AWS credentials",
            )
        
        return {
            "valid": True,
            "account_id": aws_provider.account_id,
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error validating AWS credentials: {str(e)}",
        )
