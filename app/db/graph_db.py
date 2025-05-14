import logging
from typing import Any, Dict, Optional

from neo4j import GraphDatabase, Driver, Session, Record, Transaction
from neo4j.exceptions import Neo4jError

from app.core.config import settings
from app.core.exceptions import DatabaseError

logger = logging.getLogger(__name__)

class Neo4jClient:
    _driver: Optional[Driver] = None

    def __init__(self, uri: str = settings.NEO4J_URI, user: str = settings.NEO4J_USER, password: str = settings.NEO4J_PASSWORD):
        self.uri = uri
        self.user = user
        self.password = password
        if not uri or not user or not password:
            logger.warning("Neo4j connection details not fully configured. Graph features will be disabled.")
            self._driver = None
        else:
            try:
                self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
                self._driver.verify_connectivity()
                logger.info(f"Neo4j driver initialized for URI: {self.uri}")
            except Neo4jError as e:
                logger.error(f"Failed to initialize Neo4j driver or verify connectivity: {e}")
                self._driver = None
                # Optionally re-raise or handle differently based on application requirements
                raise DatabaseError(f"Neo4j connection failed: {e}") from e
            except Exception as e:
                logger.error(f"An unexpected error occurred during Neo4j initialization: {e}")
                self._driver = None
                raise DatabaseError(f"Unexpected Neo4j initialization error: {e}") from e

    def close(self):
        if self._driver:
            try:
                self._driver.close()
                logger.info("Neo4j driver closed.")
            except Exception as e:
                logger.error(f"Error closing Neo4j driver: {e}")

    def get_session(self, database: str = "neo4j") -> Optional[Session]:
        if not self._driver:
            logger.warning("Neo4j driver not initialized. Cannot get session.")
            return None
        try:
            return self._driver.session(database=database)
        except Exception as e:
            logger.error(f"Failed to create Neo4j session: {e}")
            return None

    def run(self, query: str, parameters: Optional[Dict[str, Any]] = None, database: str = "neo4j") -> Optional[list[Record]]:
        if not self._driver:
            logger.warning("Neo4j driver not initialized. Cannot run query.")
            return None

        session: Optional[Session] = None
        try:
            session = self.get_session(database=database)
            if not session:
                raise DatabaseError("Failed to obtain Neo4j session.")

            # This function is passed to execute_write, it only receives the transaction (tx)
            def _execute_query_unit_of_work(tx: Transaction) -> list[Record]:
                result = tx.run(query, parameters) # query and parameters are from the outer scope
                return result.data()

            # timeout is a parameter for execute_write itself.
            records = session.execute_write(_execute_query_unit_of_work)
            logger.debug(f"Executed Cypher query: {query} with params: {parameters}")
            return records

        except Neo4jError as e:
            logger.error(f"Neo4j query failed: {e}. Query: {query}, Params: {parameters}")
            raise DatabaseError(f"Neo4j query failed: {e}") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred during Neo4j query execution: {e}")
            raise DatabaseError(f"Unexpected Neo4j query error: {e}") from e
        finally:
            if session:
                session.close()


# Dependency for FastAPI
# Global instance (or manage lifecycle with FastAPI lifespan events)
neo4j_client: Optional[Neo4jClient] = None

def get_neo4j_client() -> Optional[Neo4jClient]:
    global neo4j_client
    if neo4j_client is None:
        try:
            neo4j_client = Neo4jClient()
        except DatabaseError:
            logger.error("Failed to initialize Neo4j client dependency.")
            neo4j_client = None # Ensure it remains None if init fails
        except Exception as e:
             logger.error(f"Unexpected error initializing Neo4j client dependency: {e}")
             neo4j_client = None
    return neo4j_client

async def close_neo4j_client():
    global neo4j_client
    if neo4j_client:
        neo4j_client.close()
        neo4j_client = None
        logger.info("Neo4j client dependency closed.")

# Example Usage (for testing purposes, remove later)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        client = Neo4jClient()
        if client._driver:
            print("Neo4j Client Initialized Successfully.")
            # Test query
            try:
                client.run("MERGE (t:TestNode {name: $name}) RETURN t", parameters={"name": "Neo4jClientTest"})
                print("Test query executed successfully.")
                results = client.run("MATCH (t:TestNode {name: 'Neo4jClientTest'}) RETURN t.name AS name")
                print(f"Test query result: {results}")
                client.run("MATCH (t:TestNode {name: 'Neo4jClientTest'}) DELETE t")
                print("Test node deleted.")
            except DatabaseError as db_err:
                 print(f"Database error during test query: {db_err}")
            client.close()
        else:
            print("Neo4j Client Initialization Failed (driver not available).")

    except DatabaseError as e:
        print(f"Failed to initialize Neo4j client: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# Synchronous client getter for Celery tasks or other non-FastAPI contexts
def get_neo4j_client_sync() -> Optional[Neo4jClient]:
    """Provides a synchronous Neo4jClient instance."""
    try:
        client = Neo4jClient() # Directly instantiate
        if client._driver: # Check if driver initialized successfully
            return client
        else:
            logger.error("Failed to initialize Neo4j driver for synchronous client.")
            return None
    except DatabaseError as e:
        logger.error(f"DatabaseError initializing synchronous Neo4j client: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error initializing synchronous Neo4j client: {e}")
        return None 