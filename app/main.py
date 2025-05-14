from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import logging
import sys # Import sys

# Load .env file into environment variables BEFORE other imports
# Ensures Boto3 and other libs can find credentials if set in .env
load_dotenv()

# --- Loguru Configuration --- 
# Moved up to ensure logger is configured before other imports might use it
from loguru import logger
from app.core.config import settings

# Remove default handler
logger.remove()
# Add new handler with level from settings
log_level = settings.LOG_LEVEL.upper() if settings.LOG_LEVEL else "INFO"
# Add propagate=True to attempt to push level to standard loggers
logger.add(sys.stderr, level=log_level, format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {name}:{function}:{line} - {message}")
logger.info(f"Logger configured with level: {log_level}")
# --- End Loguru Configuration ---

from app.api.v1.api import api_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    debug=settings.DEBUG,
)

# Set up CORS
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {"message": "Welcome to AWS Cloud Posture Agent API"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
