from typing import Any, Dict, List, Optional, Union

from pydantic import AnyHttpUrl, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "AWS Cloud Posture Agent"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = []

    # Neo4j Connection
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    GRAPH_REBUILD_STRATEGY: str = "WIPE_AND_RELOAD"

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, str) and v.startswith("[") and v.endswith("]"):
            try:
                import json
                return json.loads(v.replace("'", '"'))
            except json.JSONDecodeError:
                raise ValueError("BACKEND_CORS_ORIGINS string is not valid JSON list format")
        elif isinstance(v, list):
            return v
        raise ValueError("BACKEND_CORS_ORIGINS must be a list or a comma-separated string or a JSON string list")

    # Debug settings
    DEBUG: bool = False

    # Database URL (Sprint 1+)
    DATABASE_URL: str

    # Logging Level
    LOG_LEVEL: str = "INFO" # Default to INFO, can be overridden by env var

    # Celery Settings (read from environment, set in docker-compose)
    CELERY_BROKER_URL: str = "amqp://guest:guest@localhost:5672//" # Default for local dev if not set
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"    # Default for local dev if not set

    # Blast Radius Settings
    BLAST_RADIUS_MAX_DEPTH: int = 3
    RELATIONSHIP_WEIGHTS: Dict[str, float] = {
        "CAN_ASSUME": 10.0,
        "CAN_ACCESS_FULL_ACCESS": 8.0,
        "CAN_ACCESS_PERMISSIONS": 6.0,
        "CAN_ACCESS_WRITE": 6.0,
        "CAN_ACCESS_READ": 2.0,
        "CAN_ACCESS_LIST": 2.0,
        "INSTANCE_PROFILE_FOR": 7.0,
        "ROUTES_TO": 5.0,
        "ROUTES_TO_INTERNET_GATEWAY": 7.0,
        "ROUTES_TO_NAT_GATEWAY": 6.0,
        "APPLIES_TO": 4.0,
        "SECURITY_RULE": 4.0,
        "ATTACHED_TO_INSTANCE": 1.0,
        "USES_ROLE": 3.0,
        "IN_SUBNET": 0.5,
        "IN_VPC": 0.5,
        "CONTAINS": 0.1,
        "DEFAULT": 0.1
    }

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra='ignore'
    )


settings = Settings()
