class DatabaseError(Exception):
    """Custom exception for database related errors."""
    pass

class ApiClientError(Exception):
    """Custom exception for external API client errors."""
    pass

class ConfigurationError(Exception):
    """Custom exception for configuration errors."""
    pass

# Add other custom exception classes as needed 