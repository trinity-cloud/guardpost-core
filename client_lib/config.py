import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# --- API Configuration ---
BASE_URL = os.getenv("GUARDPOST_API_URL", "http://localhost:8000/api/v1")
TEST_AWS_ACCOUNT_ID = os.getenv("GUARDPOST_TEST_ACCOUNT_ID", "YOUR_AWS_ACCOUNT_ID")
TEST_USER_EMAIL = os.getenv("GUARDPOST_TEST_USER", "testuser@example.com")
TEST_USER_PASSWORD = os.getenv("GUARDPOST_TEST_PASSWORD", "testpassword123")

# --- Neo4j Configuration ---
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "your_neo4j_password")
NEO4J_BROWSER_URL = os.getenv("GUARDPOST_NEO4J_BROWSER", "http://localhost:7474")

# --- Shared Session and Token ---
# Global session object for the client library
SESSION = requests.Session()
ACCESS_TOKEN = None # This will be set by the auth module upon successful login 