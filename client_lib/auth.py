import requests
from .config import SESSION, BASE_URL, TEST_USER_EMAIL, TEST_USER_PASSWORD
from . import config as client_config # To modify client_config.ACCESS_TOKEN

def register_user():
    """Register a new user."""
    print(f"--- [Client Lib] Attempting to register user: {TEST_USER_EMAIL} ---")
    url = f"{BASE_URL}/auth/register"
    payload = {
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }
    try:
        response = SESSION.post(url, json=payload)
        if response.status_code == 200:
            print("Registration successful (or user already exists).")
            return True # Proceed to login
        elif response.status_code == 400 and "already exists" in response.text:
             print("User already exists. Proceeding to login...")
             return True # Proceed to login
        else:
            print(f"Registration failed: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Registration request failed: {e}")
        return False

def login_user():
    """Login and store the access token in client_lib.config."""
    print(f"--- [Client Lib] Attempting to login user: {TEST_USER_EMAIL} ---")
    url = f"{BASE_URL}/auth/token"
    data = {
        "username": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    }
    try:
        response = SESSION.post(url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            # Update the ACCESS_TOKEN in the config module
            client_config.ACCESS_TOKEN = token_data.get("access_token")
            if client_config.ACCESS_TOKEN:
                print("Login successful. Token stored in client_lib.config.")
                SESSION.headers.update({"Authorization": f"Bearer {client_config.ACCESS_TOKEN}"})
                return True
            else:
                print("Login succeeded but no token received in client_lib.config.")
                return False
        else:
            print(f"Login failed: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Login request failed: {e}")
        return False 