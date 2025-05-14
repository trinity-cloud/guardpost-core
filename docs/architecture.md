# GuardPost Core Architecture

GuardPost Core is designed with a modular architecture to provide comprehensive cloud security scanning, analysis, and remediation guidance. Below is an overview of its key components and their interactions.

## Core Components

1.  **Scanners (`app/services/scanners/`)**
    *   **Responsibility:** Collect configuration data and metadata from AWS services.
    *   **Implementation:** Python modules interact with AWS APIs (via Boto3) for various services (IAM, EC2, S3, RDS, Lambda, etc.).
    *   **Output:** Raw resource data and relationship information.

2.  **Graph Database (Neo4j)**
    *   **Responsibility:** Store and model the scanned AWS resources, their configurations, and their interrelationships as a property graph.
    *   **Technology:** Neo4j graph database.
    *   **Usage:** Enables complex queries for security analysis, attack path identification (future), and understanding resource context.
    *   *(See [AWS Resource Properties](./aws_resource_properties.md) and [Graph Schema Overview](./graph_schema.md) for more details.)*

3.  **Graph Builder (`app/services/graph_builder/`)**
    *   **Responsibility:** Process the raw data from scanners and populate the Neo4j graph database according to the defined schema.
    *   **Implementation:** Transforms resource data into nodes and relationships, ensuring data integrity and consistency in the graph.

4.  **Analyzers (`app/services/analyzers/`)**
    *   **Responsibility:** Identify misconfigurations and security vulnerabilities by querying the Neo4j graph and applying security rules/logic.
    *   **Implementation:** Service-specific Python modules (e.g., `s3_analyzer.py`, `iam_analyzer.py`) that contain checks for common security issues.
    *   **Output:** Security findings with details about the issue, affected resource, and severity.

5.  **Remediation Service (`app/services/remediation/`)**
    *   **Responsibility:** Generate actionable remediation guidance for identified findings.
    *   **Output Schema:** `RemediationOutputV2` (defined in `app/services/remediation/schemas.py`).
    *   **Sub-Components:**
        *   **Rule-Based Engine:** Service-specific guidance modules (e.g., `s3_guidance.py`) provide baseline remediation steps and IaC (Terraform) snippets.
        *   **LLM Enhancement Layer (`llm_guidance.py`):**
            *   Integrates with Anthropic Claude to enrich the rule-based guidance with more detailed explanations and context-aware advice.
            *   Interacts with the LLM using structured JSON for prompts and responses.
            *   *(See [LLM Integration](./llm_integration.md) for more details.)*
        *   **Caching:** LLM-generated remediation guidance is cached in the PostgreSQL database (within the `Finding` object) to optimize performance and manage costs.

6.  **API (`app/api/`)**
    *   **Responsibility:** Expose GuardPost Core functionalities to clients.
    *   **Technology:** FastAPI.
    *   **Key Endpoints:** Secure endpoints for initiating scans, retrieving scan status, listing findings, and obtaining remediation guidance.
    *   **Authentication:** JWT-based authentication.

7.  **Database (PostgreSQL)**
    *   **Responsibility:** Store persistent application data such as scan history, finding details (including cached LLM remediation), and user information (future).
    *   **Technology:** PostgreSQL.

8.  **Asynchronous Task Processing (Celery)**
    *   **Responsibility:** Handle long-running operations like AWS resource scanning and post-scan analysis tasks (e.g., blast radius calculations - future) in the background.
    *   **Technology:** Celery with RabbitMQ as the message broker and Redis for results backend.
    *   **Benefit:** Improves API responsiveness and allows for scalable processing of intensive tasks.

## Data Flow Overview

1.  A user initiates a **Scan** via the API.
2.  A **Celery worker** picks up the scan task.
3.  **Scanners** collect data from the specified AWS account and services.
4.  The **Graph Builder** processes this data and populates/updates the **Neo4j Graph Database**.
5.  Once the graph is built, **Analyzers** query the graph to identify security **Findings**.
6.  Findings are stored in the **PostgreSQL Database**.
7.  When a user requests remediation for a finding via the API:
    *   The system first checks the PostgreSQL cache for stored LLM-enhanced guidance.
    *   If not cached or LLM is disabled: The **Rule-Based Remediation Engine** generates baseline `RemediationOutputV2` guidance.
    *   If LLM is enabled and no suitable cache: The baseline guidance is passed to the **LLM Enhancement Layer**, which interacts with Claude to produce enriched `RemediationOutputV2` guidance. This is then cached.
8.  The final `RemediationOutputV2` is returned to the user.

This architecture allows GuardPost Core to efficiently collect data, model complex cloud environments, perform sophisticated security analysis, and deliver rich, actionable remediation advice. 