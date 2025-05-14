# GuardPost Core Workflow

This document describes the typical workflow for a user interacting with GuardPost Core to scan their AWS environment, identify findings, and get remediation guidance.

## 1. Setup and Configuration

*   **Prerequisites:** Ensure Docker and Docker Compose are installed if using the recommended Docker setup.
*   **Clone Repository:** Clone the `guardpost-core` repository from GitHub.
*   **Environment Configuration (`.env` file):**
    *   Copy the `.env.example` file to `.env`.
    *   Review and update essential variables, especially:
        *   `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`
        *   `SECRET_KEY` (generate a strong, unique key for JWT authentication).
        *   AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`) if you intend the application itself to use these directly (e.g., for some types of scans or operations). Alternatively, ensure your environment (e.g., EC2 instance profile or local AWS CLI configuration) provides credentials that Boto3 can discover.
    *   **LLM Configuration (Optional):**
        *   `ENABLE_LLM_REMEDIATION=true` (to enable LLM-enhanced guidance).
        *   `ANTHROPIC_API_KEY="your_claude_api_key"` (if LLM enhancement is enabled).
*   **Launch Services:** Start GuardPost Core services using `docker-compose up --build -d`.

## 2. User Authentication (API Client)

*   The primary interaction with GuardPost Core is via its API.
The `client.py` script demonstrates this flow:
*   **Registration/Login:** The client first attempts to register a new user (e.g., `testuser@example.com`) or login if the user already exists.
*   **Token Retrieval:** Upon successful login, an access token (JWT) is retrieved.
*   **Token Usage:** This token is then used in the `Authorization` header (as a Bearer token) for all subsequent API requests.
    *   *(Refer to `client_lib/auth.py` for the client-side implementation and `app/api/v1/endpoints/auth.py` for the server-side logic.)*

## 3. Initiating a Scan

*   **API Endpoint:** `POST /api/v1/scans/`
*   **Action:** Users (or the `client.py` script) send a request to this endpoint to start a new security scan.
*   **Parameters:**
    *   `aws_account_id`: The AWS account ID to be scanned.
    *   `scan_type`: (e.g., `standard` - determines the depth or breadth of scanning).
    *   `regions` (Optional): Specific AWS regions to scan.
    *   `services` (Optional): Specific AWS services to scan (e.g., `s3`, `iam`, `ec2`).
*   **Process:** This request triggers an asynchronous task managed by Celery. The API returns a `scan_id` immediately.

## 4. Monitoring Scan Progress

*   **API Endpoint:** `GET /api/v1/scans/{scan_id}/status`
*   **Action:** Users can poll this endpoint using the `scan_id` to check the status of the ongoing scan.
*   **Output:** Provides the current status (e.g., `PENDING`, `IN_PROGRESS`, `COMPLETED`, `FAILED`) and potentially a progress percentage.

## 5. Retrieving Findings

*   **API Endpoint:** `GET /api/v1/findings/`
*   **Action:** Once a scan is `COMPLETED`, users can retrieve the identified security findings.
*   **Parameters (Filtering):**
    *   `scan_id`: To get findings for a specific scan.
    *   `severity`: (e.g., `CRITICAL`, `HIGH`).
    *   `category`: (e.g., `IAM`, `S3_PUBLIC_EXPOSURE`).
    *   `resource_id`, `resource_type`, `region`, `account_id`.
    *   Pagination (`skip`, `limit`).
*   **Output:** A list of finding objects, each detailing a specific security issue.

## 6. Requesting and Interpreting Remediation Guidance

*   **API Endpoint:** `GET /api/v1/findings/{finding_id}/remediation`
*   **Action:** For a specific `finding_id`, users request detailed remediation guidance.
*   **Output (`RemediationOutputV2` schema):**
    *   `finding_id`: The ID of the finding.
    *   `schema_version`: Currently "2.0".
    *   `is_llm_enhanced`: Boolean indicating if the guidance was augmented by an LLM.
    *   `issue_summary`: A concise summary of the security issue.
    *   `technical_details`: A more in-depth explanation of the vulnerability and its risks.
    *   `manual_steps`: A list of step-by-step instructions for manual remediation via the AWS console or CLI.
    *   `iac_remediation` (Optional):
        *   `tool`: The IaC tool (e.g., `terraform`).
        *   `code_snippet`: The actual IaC code to fix the issue.
        *   `apply_instructions`: How to use the provided snippet.
    *   `risk_score` (Optional): Placeholder for future risk scoring.
    *   `impact_analysis` (Optional): Placeholder for future impact analysis (blast radius, etc.).
    *   `compliance_standards`: Relevant compliance frameworks (e.g., CIS).
    *   `reference_links`: URLs to AWS documentation or best practice guides.
*   **Client Display:** The `client.py` script (using `client_lib/findings.py`) parses this `RemediationOutputV2` object and displays the information in a user-friendly format, indicating whether the guidance was LLM-enhanced or rule-based.

## 7. Exploring the Graph (Optional, Advanced)

*   Users can connect directly to the Neo4j database (e.g., via the Neo4j Browser at `http://localhost:7474`) to perform custom Cypher queries and explore the resource relationship graph built by GuardPost Core for deeper, ad-hoc analysis.

This workflow enables users to systematically assess their AWS security posture, understand identified risks, and receive actionable guidance to remediate them effectively. 