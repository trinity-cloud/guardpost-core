import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Optional, Any
import uuid

from loguru import logger


class AwsProvider:
    """
    Provider for AWS services that handles authentication and session management.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
    ):
        """
        Initialize AWS provider.
        
        Priority for session creation:
        1. Use `profile_name` if provided.
        2. Use default credential chain (env vars, shared files, instance profile) if no profile.
        3. If `role_arn` is provided, assume the role using credentials from step 1 or 2.

        Args:
            region: Default AWS region to use.
            profile_name: Optional AWS profile name (from ~/.aws/credentials or ~/.aws/config).
            role_arn: Optional ARN of the IAM role to assume.
        """
        self._profile_name = profile_name
        self._role_arn = role_arn
        self.region = region
        self.session = self._create_session()
        self.account_id = self._get_account_id()
        
    def _create_session(self) -> boto3.Session:
        """
        Creates the Boto3 session, handling profile selection and role assumption.
        Priority:
        1. Use specified profile if provided.
        2. Use default credential chain otherwise.
        3. Assume specified role if ARN is provided, using credentials from #1 or #2.
        """
        initial_session: boto3.Session
        final_session: boto3.Session

        try:
            # Step 1 & 2: Create the initial session (based on profile or default chain)
            if self._profile_name:
                logger.info(f"Attempting to create initial AWS session using profile: {self._profile_name}")
                try:
                    initial_session = boto3.Session(profile_name=self._profile_name)
                    logger.debug(f"Successfully created session with profile: {self._profile_name}")
                except Exception as e: # Catch broader exceptions like ProfileNotFound or credential errors
                    logger.error(f"Failed to create session using profile '{self._profile_name}': {e}")
                    raise ConnectionError(f"Failed to initialize AWS session using profile '{self._profile_name}'. Check profile existence and credentials.") from e
            else:
                logger.info("Attempting to create initial AWS session using default credential chain.")
                try:
                    initial_session = boto3.Session() # Uses default chain
                    # Basic validation by checking region (optional)
                    _ = initial_session.region_name
                    logger.debug("Successfully created session with default credentials.")
                except Exception as e:
                    logger.error(f"Failed to create session using default credentials: {e}")
                    raise ConnectionError("Failed to initialize AWS session using default credentials. Check environment variables, ~/.aws files, or instance profile.") from e

            # Step 3: Assume role if ARN is provided
            if self._role_arn:
                logger.info(f"Attempting to assume role: {self._role_arn}")
                try:
                    sts_client = initial_session.client('sts')
                    # Generate a unique, compliant session name
                    # Using first part of uuid for brevity + prefix. Ensure it's <= 64 chars.
                    scan_id_part = str(uuid.uuid4()).split('-')[0]
                    role_session_name = f"cspm-scan-{scan_id_part}"[:64]
                    
                    logger.debug(f"Assuming role with RoleArn='{self._role_arn}', RoleSessionName='{role_session_name}'")
                    response = sts_client.assume_role(
                        RoleArn=self._role_arn,
                        RoleSessionName=role_session_name
                    )
                    temp_creds = response.get('Credentials')
                    if not temp_creds:
                        logger.error(f"AssumeRole call succeeded but no credentials were returned for role {self._role_arn}.")
                        raise ConnectionError(f"AssumeRole call succeeded but no credentials returned for role {self._role_arn}")

                    logger.info(f"Successfully assumed role {self._role_arn}. Creating session with temporary credentials.")
                    final_session = boto3.Session(
                        aws_access_key_id=temp_creds['AccessKeyId'],
                        aws_secret_access_key=temp_creds['SecretAccessKey'],
                        aws_session_token=temp_creds['SessionToken'],
                        region_name=self.region # Use the initially configured region
                    )
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code')
                    logger.error(f"Failed to assume role '{self._role_arn}'. STS Error Code: {error_code}, Message: {e}")
                    raise ConnectionError(f"Failed to assume role '{self._role_arn}'. Ensure the initial credentials have 'sts:AssumeRole' permission for this role. Error: {e}") from e
                except Exception as e:
                     logger.error(f"An unexpected error occurred during role assumption for '{self._role_arn}': {e}")
                     raise ConnectionError(f"Unexpected error assuming role '{self._role_arn}'.") from e
            else:
                # No role assumption needed, use the initial session
                logger.debug("No role assumption requested. Using initial session.")
                final_session = initial_session
                # Ensure the final session uses the configured region if the initial default didn't pick one up correctly
                if final_session.region_name is None:
                     final_session = boto3.Session(region_name=self.region)
                     logger.debug(f"Applied configured region '{self.region}' to default session.")
                elif self.region and final_session.region_name != self.region:
                     logger.warning(f"Session region '{final_session.region_name}' differs from configured region '{self.region}'. Using session region.")
                     # Alternatively, force override: final_session = boto3.Session(region_name=self.region)

            # Final validation (optional but recommended)
            try:
                 sts_final = final_session.client('sts')
                 sts_final.get_caller_identity()
                 logger.info("Final AWS session validated successfully.")
            except Exception as e:
                logger.error(f"Validation failed for the final AWS session: {e}")
                raise ConnectionError("Failed to validate the final AWS session credentials.") from e

            return final_session

        except ConnectionError: # Re-raise specific connection errors
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during AWS session creation: {e}")
            raise ConnectionError("Unexpected error creating AWS session.") from e
    
    def _get_account_id(self) -> str:
        """
        Get the AWS account ID for the current session.
        """
        if not self.session:
            logger.error("Cannot get account ID: AWS session is not initialized.")
            raise ConnectionError("AWS session not initialized before getting account ID.")
        try:
            sts_client = self.session.client("sts")
            return sts_client.get_caller_identity()["Account"]
        except ClientError as e:
            logger.error(f"Failed to get AWS account ID using the final session: {str(e)}")
            raise ConnectionError(f"Failed to get AWS account ID. Check session credentials/permissions. Error: {e}") from e
        except Exception as e:
             logger.error(f"Unexpected error getting AWS account ID: {e}")
             raise ConnectionError("Unexpected error getting AWS account ID.") from e

    def get_client(self, service_name: str, region: Optional[str] = None) -> Any:
        """
        Get a boto3 client for the specified AWS service.
        
        Args:
            service_name: Name of the AWS service
            region: Optional region override
            
        Returns:
            Boto3 client for the specified service
        """
        try:
            return self.session.client(service_name, region_name=region or self.region)
        except Exception as e:
            logger.error(f"Failed to create client for {service_name}: {str(e)}")
            raise
    
    def get_resource(self, service_name: str, region: Optional[str] = None) -> Any:
        """
        Get a boto3 resource for the specified AWS service.
        
        Args:
            service_name: Name of the AWS service
            region: Optional region override
            
        Returns:
            Boto3 resource for the specified service
        """
        try:
            return self.session.resource(service_name, region_name=region or self.region)
        except Exception as e:
            logger.error(f"Failed to create resource for {service_name}: {str(e)}")
            raise

    def list_regions(self) -> List[str]:
        """
        List all available AWS regions.
        
        Returns:
            List of region names
        """
        try:
            ec2_client = self.get_client("ec2")
            response = ec2_client.describe_regions()
            return [region["RegionName"] for region in response["Regions"]]
        except ClientError as e:
            logger.error(f"Failed to list AWS regions: {str(e)}")
            raise
    
    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials by making a simple API call.
        
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            sts_client = self.get_client("sts")
            sts_client.get_caller_identity()
            return True
        except ClientError:
            return False
