from typing import Dict, Any, Callable, Union, List, Optional
from app.db import models
from .schemas import (
    RemediationOutputV2, 
    IacRemediation,
    IacTool  # Added IacTool
    # Removed ManualRemediationSteps, ComplianceStandard, ReferenceLink as they are not in schemas.py for V2
)

# --- Lambda Guidance Functions (V2) ---

def get_lambda_sensitive_env_vars_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id)
    sensitive_keys = details.get("sensitive_keys_found", [])
    runtime = details.get("runtime", "N/A")

    issue_summary = f"Lambda function '{function_name}' has potentially sensitive data stored in environment variables."
    
    technical_details_list = [
        f"Function Name: {function_name}",
        f"Function ARN: {finding.resource_id}",
        f"Runtime: {runtime}",
        f"Detected sensitive keys: {', '.join(sensitive_keys) if sensitive_keys else 'None specifically identified, but review all variables.'}",
        "Storing secrets (like API keys, database passwords, tokens) directly in Lambda environment variables is a security risk, as they can be exposed through console access or if the function's code is compromised."
    ]

    manual_steps_content = [
        "**Review Environment Variables:**",
        f"1. Navigate to the AWS Lambda console, select the function: '{function_name}'.",
        "2. Go to the 'Configuration' tab, then 'Environment variables'.",
        "3. Identify variables that store sensitive information (e.g., passwords, API keys).",
        "**Secure Secret Storage:**",
        "4. Store these secrets in AWS Secrets Manager or AWS Systems Manager Parameter Store (SecureString type).",
        "5. Grant the Lambda function's execution role IAM permissions to read these secrets (e.g., `secretsmanager:GetSecretValue` or `ssm:GetParameter`).",
        "**Update Lambda Function:**",
        "6. Modify your Lambda function code to fetch these secrets from Secrets Manager or Parameter Store at runtime.",
        "7. Remove the sensitive environment variables from the Lambda function configuration.",
        "   - Via Console: Edit and remove variables.",
        "   - Via AWS CLI: `aws lambda update-function-configuration --function-name <function-name> --environment Variables={{KEY1=val1,...}}` (omitting sensitive ones). Ensure you replace placeholders. Note: CLI for complex environment variables can be tricky; prefer console or IaC.",
        "**CloudFormation Note:**",
        "8. If using CloudFormation, update the `Environment.Variables` section of your `AWS::Lambda::Function` resource. Remove sensitive variables and ensure your Lambda code fetches them from a secure store. Example snippet for passing a secret ARN:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaFunction:",
        "       Type: AWS::Lambda::Function",
        "       Properties:",
        "         FunctionName: my-secure-function",
        "         # ... other configurations ...",
        "         Environment:",
        "           Variables:",
        "             # API_KEY: \"sensitive_value\" # BAD PRACTICE",
        "             SECRET_ARN: !Sub \"arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:your_api_key_secret-XXXXXX\" # Replace",
        "         # Ensure role has permissions for secretsmanager:GetSecretValue",
        "   ```"
    ]

    # Primary IaC example (Terraform)
    iac_tf_snippet = f"""resource "aws_lambda_function" "example" {{
  function_name = "{function_name}"
  # ... other configurations ...

  # Avoid storing secrets directly in environment variables
  # environment {{
  #   variables = {{
  #     API_KEY = "sensitive_value" # BAD PRACTICE
  #   }}
  # }}

  # Instead, fetch from Secrets Manager or Parameter Store in your code.
  # Grant necessary IAM permissions to the Lambda execution role.
  # Example of passing a secret ARN (to be fetched by code):
  environment {{
    variables = {{
      SECRET_ARN = "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:your_api_key_secret-XXXXXX" # Replace with your actual secret ARN
      # PARAMETER_NAME = "/myapp/dev/api_key" # Or a parameter name
    }}
  }}
}}

# Example IAM policy statement for the Lambda execution role (add to existing role)
# resource "aws_iam_role_policy_attachment" "lambda_secrets_access" {{
#   role       = aws_lambda_function.example.role
#   policy_arn = aws_iam_policy.secrets_access_policy.arn
# }}

# resource "aws_iam_policy" "secrets_access_policy" {{
#   name        = "LambdaSecretsAccessPolicy"
#   description = "Allows Lambda to access specific secrets"
#   policy      = jsonencode({{
#     Version   = "2012-10-17"
#     Statement = [
#       {{
#         Effect   = "Allow"
#         Action   = "secretsmanager:GetSecretValue"
#         Resource = "arn:aws:secretsmanager:REGION:ACCOUNT_ID:secret:your_api_key_secret-XXXXXX" # Specific secret ARN
#       }},
#       # {{
#       #   Effect   = "Allow"
#       #   Action   = "ssm:GetParameter"
#       #   Resource = "arn:aws:ssm:REGION:ACCOUNT_ID:parameter/myapp/dev/api_key" # Specific parameter ARN
#       # }}
#     ]
#   }})
# }}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0", # Example provider version
        apply_instructions="1. Integrate this Terraform code into your existing Lambda function definition.\n2. Ensure the Lambda execution role has IAM permissions to access the specified secret in AWS Secrets Manager or parameter in SSM Parameter Store.\n3. Replace placeholder ARNs and names with your actual resource identifiers.\n4. Run `terraform plan` and `terraform apply`."
    )

    compliance_standards_list = [
        "CIS AWS Foundations Benchmark (Control 4.1): Conceptual alignment - Ensure no hardcoded secrets in Lambda environment variables.",
        "AWS Well-Architected Framework (Security Pillar): Manage secrets securely."
    ]

    reference_links_list = [
        "AWS Lambda Environment Variables Security: https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-security",
        "AWS Secrets Manager: https://aws.amazon.com/secrets-manager/",
        "AWS Systems Manager Parameter Store: https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html",
        "Terraform AWS Lambda Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function",
        "Terraform AWS Secrets Manager Data Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret_version"
    ]

    return RemediationOutputV2(
        # schema_version="2.0", # This is automatically set by Pydantic if default is provided in model
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        # impact_analysis: Optional[ImpactAnalysis] = Field(None, ...), # Not populated yet
        iac_remediation=populated_iac_remediation, # Populated with Terraform
        manual_steps=manual_steps_content, # Includes CLI and CFN notes now
        # risk_score: Optional[RiskScore] = Field(None, ...), # Not populated yet
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

def get_lambda_unauthorized_invocation_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id)
    stmt_sid = details.get("statement_sid", "N/A")
    actions = details.get("statement_actions", "N/A")
    aws_principals = details.get("statement_aws_access", [])
    service_principals = details.get("statement_service_access", [])
    has_wildcard = details.get("statement_has_wildcard_principal", False)
    conditions = details.get("statement_conditions", {})

    issue_summary = f"Lambda function '{function_name}' resource policy (SID: {stmt_sid}) may allow unauthorized invocation."
    
    technical_details_list = [
        f"Function Name: {function_name}",
        f"Function ARN: {finding.resource_id}",
        f"Problematic Statement ID (SID): {stmt_sid}",
        f"Allowed Actions: {actions}",
        f"Principals (AWS): {aws_principals if aws_principals else 'None'}",
        f"Principals (Service): {service_principals if service_principals else 'None'}",
        f"Has Wildcard Principal ('*'): {'Yes' if has_wildcard else 'No'}",
        f"Conditions: {conditions if conditions else 'None'}",
        "A permissive resource-based policy can allow unintended AWS accounts, services, or even anonymous users (if combined with Function URLs) to invoke the Lambda function."
    ]

    manual_steps_content = [
        "**Review Lambda Function Policy:**",
        f"1. Navigate to the AWS Lambda console, select the function: '{function_name}'.",
        "2. Go to the 'Configuration' tab, then 'Permissions'.",
        "3. Under 'Resource-based policy statements', review the policies. Identify the statement with SID: '{stmt_sid}'.",
        "**Modify or Remove Problematic Statement:**",
        "4. If the statement grants overly broad permissions (e.g., to Principal '*' without adequate conditions, or to untrusted accounts/services):",
        "   a. **Modify (Console/CLI):** You can attempt to edit the policy statement directly in the console if the UI supports it for the specific policy type. More reliably, use the AWS CLI: `aws lambda remove-permission --function-name {function_name} --statement-id {stmt_sid}` then `aws lambda add-permission ...` with corrected parameters.",
        "   b. **Remove (Console/CLI):** Click 'Delete' for the statement in the console or use the AWS CLI command: `aws lambda remove-permission --function-name {function_name} --statement-id {stmt_sid}`.",
        "**Principle of Least Privilege:**",
        "5. Ensure the policy grants only necessary permissions to trusted entities. For example:",
        "   - If invoked by a specific S3 bucket event: Principal `s3.amazonaws.com`, Action `lambda:InvokeFunction`, Condition `ArnLike` for `AWS:SourceArn` with the bucket ARN, and `StringEquals` for `AWS:SourceAccount`.",
        "   - If invoked by API Gateway: Principal `apigateway.amazonaws.com`, Condition `ArnLike` for `AWS:SourceArn` with the API Gateway ARN.",
        "   - If invoked by specific IAM roles/users: Principal should be the specific ARN of that role/user.",
        "**CloudFormation Note:**",
        "6. If using CloudFormation, review your `AWS::Lambda::Permission` resources. Modify or remove the problematic permission. Example of a more restrictive permission:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaS3InvokePermission:",
        "       Type: AWS::Lambda::Permission",
        "       Properties:",
        "         Action: lambda:InvokeFunction",
        "         FunctionName: !Ref MyLambdaFunction # or !GetAtt MyLambdaFunction.Arn",
        "         Principal: s3.amazonaws.com",
        "         SourceArn: !Sub \"arn:aws:s3:::your-bucket-name/*\" # Be specific",
        "         SourceAccount: !Ref AWS::AccountId",
        "         StatementId: AllowS3InvokeSecure",
        "   ```"
    ]

    iac_tf_snippet = f"""# Example of a potentially problematic aws_lambda_permission
# resource "aws_lambda_permission" "allow_public_invoke" {{
#   statement_id  = "AllowPublicInvoke"
#   action        = "lambda:InvokeFunction"
#   function_name = "{function_name}" # or aws_lambda_function.example.function_name
#   principal     = "*" # Overly permissive
# }}

# Example of a more restrictive aws_lambda_permission for S3 invocation
resource "aws_lambda_permission" "allow_s3_invoke" {{
  statement_id  = "AllowS3Invoke_{function_name}" # Ensure unique SID
  action        = "lambda:InvokeFunction"
  function_name = "{function_name}" # Or reference your aws_lambda_function resource
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::your-bucket-name/*" # Replace with specific bucket ARN or pattern
  source_account = "YOUR_ACCOUNT_ID" # Replace with your account ID
}}

# Example for API Gateway invocation
# resource "aws_lambda_permission" "allow_api_gateway_invoke" {{
#   statement_id  = "AllowAPIGatewayInvoke_{function_name}"
#   action        = "lambda:InvokeFunction"
#   function_name = "{function_name}"
#   principal     = "apigateway.amazonaws.com"
#   source_arn    = "arn:aws:execute-api:REGION:ACCOUNT_ID:API_ID/*/*/*" # Replace with your API Gateway ARN pattern
# }}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions="1. Review the provided Terraform `aws_lambda_permission` resource examples.\n2. Adapt the example that matches your intended invocation pattern (e.g., S3, API Gateway), or create a new one based on least privilege principles.\n3. Replace placeholders like function name, SIDs, ARNs, and account IDs with your specific values.\n4. Remove any overly permissive `aws_lambda_permission` resources currently associated with this function.\n5. Add the new, correctly scoped permission resource to your Terraform configuration.\n6. Run `terraform plan` and `terraform apply`."
    )

    compliance_standards_list = [
        "CIS AWS Foundations Benchmark (Control 1.22): Ensure IAM policies are attached only to groups or roles (conceptual: applies to restricting access via resource policies too).",
        "AWS Well-Architected Framework (Security Pillar): Apply least privilege."
    ]

    reference_links_list = [
        "AWS Lambda Resource-based Policies: https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html",
        "Example: S3 permissions for Lambda: https://docs.aws.amazon.com/lambda/latest/dg/services-s3-permissions.html",
        "Terraform AWS Lambda Permission Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )


def get_lambda_public_url_no_auth_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    # Assuming function_name might be in details; otherwise, resource_id is often the ARN or name.
    function_name = details.get("function_name", finding.resource_id.split(':')[-1]) 

    issue_summary = f"Lambda Function URL for '{function_name}' allows unauthenticated public access."
    
    technical_details_list = [
        f"Function Name/ARN: {finding.resource_id}",
        "The Lambda Function URL is configured with `AuthType: NONE`.",
        "This makes the HTTPS endpoint publicly accessible without any authentication, which is a significant security risk unless explicitly intended and secured by other means (e.g., within the function code, which is not standard for this feature).",
        "Best practice is to use `AuthType: AWS_IAM` and control access via IAM policies, or use API Gateway for more complex auth scenarios."
    ]

    manual_steps_content = [
        f"**1. Identify the Lambda Function:** Navigate to the AWS Lambda console and select the function: '{function_name}'.",
        "**2. Access Function URL Configuration:** Go to the 'Configuration' tab, then 'Function URL'.",
        "**3. Update Authentication Type:**",
        "   - Click 'Edit'.",
        "   - Change 'Auth type' from 'NONE' to 'AWS_IAM'.",
        "   - Click 'Save'.",
        "**4. Grant Invoke Permissions (if using AWS_IAM):**",
        "   - After setting AuthType to AWS_IAM, you must grant specific IAM principals (users/roles) permission to invoke the function URL.",
        "   - This is typically done by adding a resource-based policy to the Lambda function (using `lambda:InvokeFunctionUrl` action) or by attaching an identity-based policy to the principal.",
        "   - The required permission is `lambda:InvokeFunctionUrl` on the function URL's ARN (e.g., `arn:aws:lambda:REGION:ACCOUNT_ID:function:FUNCTION_NAME:URL_QUALIFIER`). The URL_QUALIFIER is often an alias name or `$LATEST`.",
        "**Alternative - Use API Gateway:** If you need public access with more advanced features (API keys, custom authorizers, WAF integration, rate limiting), consider deleting the Function URL and fronting your Lambda with an Amazon API Gateway endpoint.",
        "**Alternative - Delete Function URL:** If the Function URL is not needed, delete it:",
        "   - In the 'Function URL' configuration page, click 'Delete'.",
        "   - Confirm deletion.",
        f"   - CLI: `aws lambda delete-function-url-config --function-name {function_name}`",
        "**CloudFormation Note:**",
        "10. To configure with `AWS_IAM` auth type in CloudFormation:",
        "    ```yaml",
        "    Resources:",
        "      MyLambdaFunctionUrl:",
        "        Type: AWS::Lambda::Url",
        "        Properties:",
        "          TargetFunctionArn: !Ref MyLambdaFunction # or !GetAtt MyLambdaFunction.Arn",
        "          AuthType: AWS_IAM # Changed from NONE",
        "      MyLambdaUrlInvokePermission: # If AuthType is AWS_IAM",
        "        Type: AWS::Lambda::Permission",
        "        Properties:",
        "          Action: lambda:InvokeFunctionUrl",
        "          FunctionName: !Ref MyLambdaFunction",
        "          Principal: \"arn:aws:iam::YOUR_ACCOUNT_ID:role/YourInvokingRole\" # Example Principal",
        "          FunctionUrlAuthType: AWS_IAM", # Required when action is InvokeFunctionUrl
        "          StatementId: AllowSpecificRoleToInvokeFunctionUrl", # Ensure unique SID
        "    ```"
    ]
    
    iac_tf_snippet = f"""resource "aws_lambda_function_url" "example" {{
  function_name      = "{function_name}" # Or aws_lambda_function.example.function_name
  authorization_type = "AWS_IAM" # Changed from "NONE"

  # Optional: Configure CORS if needed
  # cors {{
  #   allow_credentials = true
  #   allow_origins     = ["https://example.com"]
  #   allow_methods     = ["POST"]
  #   allow_headers     = ["content-type"]
  #   expose_headers    = ["keep-alive", "date"]
  #   max_age           = 86400
  # }}
}}

# Then, use aws_lambda_permission to grant invoke access if using AWS_IAM
resource "aws_lambda_permission" "allow_url_invoke" {{
  statement_id       = "AllowSpecificRoleToInvokeUrl_{function_name}" # Ensure unique SID
  action             = "lambda:InvokeFunctionUrl"
  function_name      = "{function_name}" # Or aws_lambda_function.example.function_name
  principal          = "arn:aws:iam::YOUR_ACCOUNT_ID:role/YourInvokingRole" # Example: specific IAM role ARN
  # Or for a specific user: "arn:aws:iam::YOUR_ACCOUNT_ID:user/YourUserName"
  # Or for the entire AWS account (use with caution): "YOUR_ACCOUNT_ID"
  function_url_auth_type = "AWS_IAM" # Required when action is InvokeFunctionUrl and principal is not a service like S3/APIGateway for InvokeFunction

  # source_account is generally not used with function_url_auth_type = "AWS_IAM" for non-service principals
}}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions=(
            "1. Update the `aws_lambda_function_url` resource to set `authorization_type = \"AWS_IAM\"`.\n"
            "2. Add an `aws_lambda_permission` resource to grant specific principals the `lambda:InvokeFunctionUrl` permission.\n"
            "3. Replace placeholders for function name, principal ARN, and account ID.\n"
            "4. If the Function URL is not needed at all, consider deleting the `aws_lambda_function_url` resource entirely.\n"
            "5. Run `terraform plan` and `terraform apply`."
        )
    )

    compliance_standards_list = [
        "AWS Well-Architected Framework (Security Pillar): Apply least privilege.",
        "GuardPost Best Practice: Avoid unauthenticated Lambda Function URLs unless specifically required and mitigated."
    ]

    reference_links_list = [
        "AWS Lambda Function URL Authentication and Authorization: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
        "AWS Lambda Resource-based Policies for URL invocation: https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html#lambda-permissions-resource-based",
        "Terraform aws_lambda_function_url Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function_url",
        "Terraform aws_lambda_permission Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type, # Should be AWS::Lambda::Function or similar
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

def get_lambda_tracing_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id.split(':')[-1])

    issue_summary = f"AWS X-Ray active tracing is not enabled for Lambda function '{function_name}'."
    technical_details_list = [
        f"Function Name/ARN: {finding.resource_id}",
        "Active tracing with AWS X-Ray allows Lambda to sample invocations and send trace data, helping in debugging, performance analysis, and monitoring distributed applications.",
        "Without tracing, it's harder to pinpoint issues or understand request flows involving this Lambda function.",
        "Enabling tracing requires the function's execution role to have X-Ray write permissions (e.g., `xray:PutTraceSegments`, `xray:PutTelemetryRecords`). The `AWSXRayDaemonWriteAccess` managed policy provides these."
    ]

    manual_steps_content = [
        f"**1. Identify the Lambda Function:** Navigate to the AWS Lambda console and select the function: '{function_name}'.",
        "**2. Enable Active Tracing (Console):**",
        "   - Go to the 'Configuration' tab, then 'Monitoring and operations tools'.",
        "   - Click 'Edit' in the 'AWS X-Ray' section.",
        "   - Check the 'Active tracing' box.",
        "   - Click 'Save'.",
        "**3. Ensure IAM Permissions:** The function's execution role needs permissions to send data to X-Ray. If not already present, attach the `AWSXRayDaemonWriteAccess` managed policy to the role, or add a custom inline policy with `xray:PutTraceSegments` and `xray:PutTelemetryRecords` actions for `Resource: \"*\"`.",
        f"**4. Enable Active Tracing (AWS CLI):** `aws lambda update-function-configuration --function-name {function_name} --tracing-config Mode=Active`",
        "**5. (Optional) Instrument Code:** For more detailed traces (e.g., custom subsegments), use the AWS X-Ray SDK within your Lambda function code.",
        "**6. (Optional) Consider ADOT:** For more advanced or customizable tracing, consider using the AWS Distro for OpenTelemetry (ADOT) Lambda layer and SDK.",
        "**CloudFormation Note:**",
        "7. To enable active tracing in CloudFormation:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaFunction:",
        "       Type: AWS::Lambda::Function",
        "       Properties:",
        "         FunctionName: my-traced-function",
        "         # ... other configurations ...",
        "         TracingConfig:",
        "           Mode: Active",
        "         # Ensure the execution Role has AWSXRayDaemonWriteAccess policy or equivalent permissions.",
        "   ```"
    ]

    iac_tf_snippet = f"""resource "aws_lambda_function" "example" {{
  function_name = "{function_name}"
  # ... other configurations ...
  # Ensure the execution role (aws_iam_role.lambda_exec.arn) is defined elsewhere
  role = aws_iam_role.lambda_exec.arn 

  tracing_config {{
    mode = "Active"
  }}
}}

# Ensure the Lambda execution role has X-Ray permissions.
# Example: Attach the AWS managed policy for X-Ray daemon access.
resource "aws_iam_role_policy_attachment" "xray_attachment" {{
  role       = aws_iam_role.lambda_exec.name # Assuming aws_iam_role.lambda_exec is your role
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}}

# Or define a custom policy (less common for basic X-Ray setup)
# resource "aws_iam_policy" "lambda_xray_policy" {{
#   name        = "{function_name}-XRayPolicy"
#   description = "Policy to allow Lambda to send traces to X-Ray"
#   policy = jsonencode({{
#     Version = "2012-10-17"
#     Statement = [
#       {{
#         Effect   = "Allow"
#         Action   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
#         Resource = "*" # X-Ray daemon typically requires "*"
#       }},
#     ]
#   }})
# }}
# resource "aws_iam_role_policy_attachment" "custom_xray_attachment" {{
#   role       = aws_iam_role.lambda_exec.name
#   policy_arn = aws_iam_policy.lambda_xray_policy.arn
# }}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions=(
            "1. Add or update the `tracing_config` block within your `aws_lambda_function` resource, setting `mode = \"Active\"`.\n"
            "2. Ensure the IAM role used by the Lambda function has the `AWSXRayDaemonWriteAccess` managed policy attached, or equivalent custom permissions (`xray:PutTraceSegments`, `xray:PutTelemetryRecords` on `Resource: \"*\"`).\n"
            "3. Replace placeholders for function name and role name/ARN if necessary.\n"
            "4. Run `terraform plan` and `terraform apply`."
        )
    )

    compliance_standards_list = [
        "AWS Well-Architected Framework (Operational Excellence Pillar): Refine operations procedures frequently (tracing aids this).",
        "AWS Well-Architected Framework (Performance Efficiency Pillar): Monitor resources to ensure they meet performance targets (tracing aids this)."
    ]

    reference_links_list = [
        "AWS Lambda Function Tracing with X-Ray: https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html",
        "AWS X-Ray: https://aws.amazon.com/xray/",
        "Terraform aws_lambda_function tracing_config: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#tracing_config",
        "AWSXRayDaemonWriteAccess Managed Policy: https://docs.aws.amazon.com/xray/latest/devguide/security_iam_id-based-policy-examples.html#security_iam_id-based-policy-examples-managed-policies"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

def get_lambda_dlq_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id.split(':')[-1])

    issue_summary = f"Lambda function '{function_name}' does not have a Dead-Letter Queue (DLQ) configured for asynchronous invocations."
    technical_details_list = [
        f"Function Name/ARN: {finding.resource_id}",
        "For asynchronous Lambda invocations (e.g., from S3 events, SNS), if the function fails after retries, the event is discarded by default.",
        "Configuring a DLQ (an SQS queue or SNS topic) allows these failed events to be captured for analysis and reprocessing, preventing data loss.",
        "The Lambda function's execution role needs permission to send messages to the chosen SQS queue (`sqs:SendMessage`) or publish to the SNS topic (`sns:Publish`)."
    ]

    manual_steps_content = [
        f"**1. Identify the Lambda Function:** Navigate to the AWS Lambda console and select the function: '{function_name}'.",
        "**2. Create or Identify an SQS Queue or SNS Topic for DLQ:**",
        "   - If you don't have one, create an SQS standard queue or an SNS standard topic to serve as the DLQ. Note its ARN.",
        "**3. Configure DLQ for Lambda (Console):**",
        "   - Go to the Lambda function's 'Configuration' tab, then 'Asynchronous invocation'.",
        "   - Click 'Edit'.",
        "   - Under 'DLQ (Dead-letter queue)', select 'On failure'.",
        "   - For 'Resource type', choose 'Amazon SQS' or 'Amazon SNS'.",
        "   - For 'Destination', select or enter the ARN of your SQS queue or SNS topic.",
        "   - Click 'Save'.",
        "**4. Ensure IAM Permissions:** The Lambda function's execution role needs permission to send messages to the chosen DLQ target. Add an inline policy or attach a customer-managed policy to the role:",
        "   - For SQS DLQ: Allow `sqs:SendMessage` on `Resource: YOUR_SQS_QUEUE_ARN`.",
        "   - For SNS DLQ: Allow `sns:Publish` on `Resource: YOUR_SNS_TOPIC_ARN`.",
        f"**5. Configure DLQ (AWS CLI):** `aws lambda update-function-configuration --function-name {function_name} --dead-letter-config TargetArn=YOUR_DLQ_ARN` (Replace YOUR_DLQ_ARN with the SQS or SNS ARN).",
        "**6. Monitor the DLQ:** Regularly monitor the DLQ for messages. Set up alarms (e.g., CloudWatch alarm on SQS ApproximateNumberOfMessagesVisible) to get notified of failed invocations.",
        "**CloudFormation Note:**",
        "7. To configure a DLQ in CloudFormation:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaDLQ:",
        "       Type: AWS::SQS::Queue",
        "       Properties:",
        "         QueueName: !Sub \"${MyLambdaFunction}-dlq\"",
        "     MyLambdaFunction:",
        "       Type: AWS::Lambda::Function",
        "       Properties:",
        "         # ... other function properties ...",
        "         DeadLetterConfig:",
        "           TargetArn: !GetAtt MyLambdaDLQ.Arn",
        "         # Ensure the Lambda Execution Role has sqs:SendMessage to MyLambdaDLQ.Arn",
        "   ```"
    ]

    iac_tf_snippet = f"""resource "aws_sqs_queue" "lambda_dlq_{function_name}" {{
  name = "{function_name}-dlq"
}}

resource "aws_lambda_function" "example" {{
  function_name = "{function_name}"
  # ... other configurations ...
  # Ensure the execution role (aws_iam_role.lambda_exec.arn) is defined elsewhere
  role = aws_iam_role.lambda_exec.arn 

  dead_letter_config {{
    target_arn = aws_sqs_queue.lambda_dlq_{function_name}.arn
  }}
}}

# Ensure the Lambda execution role has permission to send messages to the DLQ.
# Example for an SQS DLQ:
resource "aws_iam_role_policy" "lambda_dlq_policy_{function_name}" {{
  name = "{function_name}-dlq-policy"
  role = aws_iam_role.lambda_exec.id # Assuming aws_iam_role.lambda_exec is your role

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action   = "sqs:SendMessage"
        Effect   = "Allow"
        Resource = aws_sqs_queue.lambda_dlq_{function_name}.arn
      }},
    ]
  }})
}}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions=(
            "1. Define an `aws_sqs_queue` (or `aws_sns_topic`) resource to serve as the DLQ.\n"
            "2. In your `aws_lambda_function` resource, add a `dead_letter_config` block, setting `target_arn` to the ARN of the DLQ.\n"
            "3. Create an `aws_iam_role_policy` and attach it to your Lambda function\'s execution role, granting `sqs:SendMessage` (or `sns:Publish`) permission to the DLQ resource.\n"
            "4. Replace placeholders for function name, role name, and DLQ name/ARN.\n"
            "5. Run `terraform plan` and `terraform apply`."
        )
    )

    compliance_standards_list = [
        "AWS Well-Architected Framework (Reliability Pillar): Design for failure, automatically recover from failure."
    ]

    reference_links_list = [
        "AWS Lambda Dead-Letter Queues: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq",
        "Terraform aws_lambda_function dead_letter_config: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#dead_letter_config",
        "Terraform aws_sqs_queue Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue",
        "Terraform aws_iam_role_policy Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

def get_lambda_reserved_concurrency_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id.split(':')[-1])
    # It might be useful if the analyzer could provide the current concurrency setting (if any) in details.

    issue_summary = f"Lambda function '{function_name}' does not have reserved concurrency configured, or it might be suboptimally configured."
    technical_details_list = [
        f"Function Name/ARN: {finding.resource_id}",
        "Without reserved concurrency, the function shares the regional unreserved concurrency pool with other functions.",
        "This can lead to throttling if other functions consume all available concurrency, or this function could inadvertently consume too much concurrency, impacting other functions or downstream services.",
        "Setting reserved concurrency guarantees a specific number of concurrent executions for this function. It also means the function cannot exceed this limit, potentially leading to throttling if set too low.",
        "A value of 0 for reserved concurrency effectively disables the function from processing new events from most event sources, except for direct synchronous invocations."
    ]

    manual_steps_content = [
        f"**1. Identify the Lambda Function:** Navigate to the AWS Lambda console and select the function: '{function_name}'.",
        "**2. Determine Appropriate Concurrency Level:** Analyze the function's expected traffic, average execution time, and the impact of potential throttling vs. resource consumption. Check CloudWatch metrics for `ConcurrentExecutions`, `Throttles`, and `Errors`.",
        "**3. Configure Reserved Concurrency (Console):**",
        "   - Go to the 'Configuration' tab, then 'Concurrency'.",
        "   - Click 'Edit'.",
        "   - Select 'Reserve concurrency'.",
        "   - Enter the desired number of reserved concurrent executions (e.g., 10, 100). The value must be >= 0.",
        "   - Click 'Save'.",
        f"**4. Configure Reserved Concurrency (AWS CLI):** `aws lambda put-function-concurrency --function-name {function_name} --reserved-concurrent-executions YOUR_VALUE` (Replace YOUR_VALUE with a non-negative integer).",
        "**5. Monitor:** After setting, monitor CloudWatch metrics like `ConcurrentExecutions`, `Throttles`, and `Invocations` for the function to ensure the reserved level is appropriate.",
        "**Considerations:**",
        "   - Reserved concurrency is deducted from your account's overall regional concurrency limit.",
        "   - If you reserve concurrency for too many functions, you might hit the regional limit for unreserved concurrency, impacting other functions.",
        "   - For bursty workloads or to reduce cold starts for latency-sensitive functions, consider Provisioned Concurrency (which has cost implications and also uses reserved concurrency).",
        "**CloudFormation Note:**",
        "   To configure reserved concurrency in CloudFormation, set the `ReservedConcurrentExecutions` property on your `AWS::Lambda::Function` resource:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaFunction:",
        "       Type: AWS::Lambda::Function",
        "       Properties:",
        "         # ... other function properties ...",
        "         ReservedConcurrentExecutions: 10 # Adjust this value as needed",
        "   ```"
    ]
    
    iac_tf_snippet = f"""# Configure reserved concurrency for a Lambda function
resource "aws_lambda_function_concurrency" "example_reserved_concurrency" {{
  function_name                     = "{function_name}" # Or aws_lambda_function.example.function_name if defined elsewhere
  reserved_concurrent_executions = 10 # Adjust this value based on your analysis. Must be >= 0.
}}

# Note: The aws_lambda_function resource itself would be defined elsewhere.
# Example placeholder for the function it applies to:
# resource "aws_lambda_function" "example" {{
#   function_name = "{function_name}"
#   # ... other configurations like handler, runtime, role etc.
# }}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions=(
            "1. Use the `aws_lambda_function_concurrency` resource to set `reserved_concurrent_executions` for your Lambda function.\n"
            "2. Replace `function_name` with the actual name of your Lambda function (or a reference to its resource if defined in the same Terraform configuration).\n"
            "3. Adjust the `reserved_concurrent_executions` value based on your function's requirements (must be >= 0). Consider starting with a conservative value and monitoring.\n"
            "4. Run `terraform plan` and `terraform apply`."
        )
    )

    compliance_standards_list = [
        "AWS Well-Architected Framework (Performance Efficiency Pillar): Monitor resources to ensure they meet performance targets, size resources to meet performance targets.",
        "AWS Well-Architected Framework (Reliability Pillar): Manage changes in automation (by defining capacity)."
    ]

    reference_links_list = [
        "Configuring Reserved Concurrency for Lambda: https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html#configuration-concurrency-reserved",
        "Terraform aws_lambda_function_concurrency Resource: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function_concurrency"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

def get_lambda_latest_runtime_guidance(finding: models.Finding) -> RemediationOutputV2:
    details = finding.details if finding.details else {}
    function_name = details.get("function_name", finding.resource_id.split(':')[-1])
    current_runtime = details.get("runtime", "an outdated version") # Analyzer should put actual current runtime here.

    issue_summary = f"Lambda function '{function_name}' is using an outdated or soon-to-be-deprecated runtime ({current_runtime})."
    technical_details_list = [
        f"Function Name/ARN: {finding.resource_id}",
        f"Current Runtime: {current_runtime}",
        "Using outdated Lambda runtimes can expose functions to security vulnerabilities that have been patched in newer versions.",
        "AWS deprecates runtimes over time, and functions using deprecated runtimes may eventually stop working or be blocked from updates.",
        "Newer runtimes often offer performance improvements, new features, and bug fixes.",
        "Migration may require code changes and thorough testing."
    ]

    manual_steps_content = [
        f"**1. Identify the Lambda Function and Current Runtime:** Note the function '{function_name}' and its current runtime '{current_runtime}'.",
        "**2. Check AWS Runtime Support Policy:** Refer to the AWS Lambda runtimes documentation (link below) to identify the latest supported Long-Term Support (LTS) version for your function's language (e.g., Python, Node.js, Java). Choose a target runtime.",
        "**3. Review Code for Compatibility:**",
        "   - Migrating (e.g., Python 3.8 to 3.12, Node.js 16.x to 20.x) may require code changes due to language updates or dependency compatibility.",
        "   - Review your function code and its dependencies for any known compatibility issues with the target runtime.",
        "**4. Update Runtime in a Test Environment (Console):**",
        "   - Create a new version or alias of your Lambda function for testing, or use a non-production environment.",
        "   - Navigate to the Lambda console, select the function/version.",
        "   - Go to 'Code source', then 'Runtime settings' (under the 'Code' tab or 'Edit runtime settings' button depending on console version) and click 'Edit'.",
        "   - Select the new target runtime from the dropdown.",
        "   - Click 'Save'.",
        f"**5. Update Runtime (AWS CLI):** `aws lambda update-function-configuration --function-name {function_name} --runtime NEW_RUNTIME_IDENTIFIER` (e.g., `python3.12`, `nodejs20.x`). Apply to a test version/alias first.",
        "**6. Test Thoroughly:** Invoke the function with various test events. Check CloudWatch Logs for errors and ensure expected behavior.",
        "**7. Deploy to Production:** Once confident, update the runtime for the production version/alias of your Lambda function.",
        "**CloudFormation Note:**",
        "8. To update the runtime in CloudFormation, modify the `Runtime` property of your `AWS::Lambda::Function` resource:",
        "   ```yaml",
        "   Resources:",
        "     MyLambdaFunction:",
        "       Type: AWS::Lambda::Function",
        "       Properties:",
        "         # ... other function properties ...",
        "         Runtime: python3.12 # Or nodejs20.x, etc. - your target runtime",
        "   ```"
    ]

    # Determine a generic placeholder for IaC snippets based on current runtime
    target_runtime_placeholder = "python3.12" # Default placeholder
    if isinstance(current_runtime, str):
        if "python" in current_runtime.lower():
            target_runtime_placeholder = "python3.12" # Example latest Python LTS
        elif "node" in current_runtime.lower():
            target_runtime_placeholder = "nodejs20.x" # Example latest Node.js LTS
        elif "java" in current_runtime.lower():
            target_runtime_placeholder = "java21" # Example latest Java LTS
        elif "go" in current_runtime.lower():
            target_runtime_placeholder = "go1.x" # Go is usually just go1.x for the latest supported
        elif "ruby" in current_runtime.lower():
            target_runtime_placeholder = "ruby3.2" # Example latest Ruby
        elif ".net" in current_runtime.lower() or "dotnet" in current_runtime.lower():
            target_runtime_placeholder = "dotnet8" # Example latest .NET

    iac_tf_snippet = f"""resource "aws_lambda_function" "example" {{
  function_name = "{function_name}"
  # ... other configurations (handler, role, etc.) ...

  runtime = "{target_runtime_placeholder}" # e.g., "python3.12", "nodejs20.x"
  # Ensure your handler and the code (e.g., from S3 or local archive) are compatible with the new runtime.
  # Dependencies may also need updates.
}}
"""
    
    populated_iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=iac_tf_snippet,
        provider_version="~> 5.0",
        apply_instructions=(
            "1. Update the `runtime` attribute in your `aws_lambda_function` resource to a newer, supported runtime identifier (e.g., `python3.12`, `nodejs20.x`).\n"
            "2. Before applying, ensure your function code and its dependencies are compatible with the target runtime. Test thoroughly in a non-production environment.\n"
            "3. Replace `function_name` and other configurations as per your setup.\n"
            "4. Run `terraform plan` and `terraform apply`."
        )
    )

    compliance_standards_list = [
        "AWS Well-Architected Framework (Security Pillar): Apply security at all layers (up-to-date runtimes are part of this).",
        "AWS Well-Architected Framework (Reliability Pillar): Automatically recover from failure (unsupported runtimes can lead to failures).",
        "Vendor Patch Management Best Practices."
    ]

    reference_links_list = [
        "AWS Lambda Runtimes and Deprecation Policy: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
        "Terraform aws_lambda_function runtime: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function#runtime"
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        account_id=finding.account_id,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        region=finding.region,
        issue_summary=issue_summary,
        technical_details='\n'.join(technical_details_list),
        iac_remediation=populated_iac_remediation,
        manual_steps=manual_steps_content,
        compliance_standards=compliance_standards_list,
        reference_links=reference_links_list
    )

# --- Lambda Guidance Map ---
# Key: (resource_type, finding_title_keyword_or_substring_from_analyzer)
LAMBDA_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], RemediationOutputV2]] = {
    # New mappings based on lambda_analyzer.py
    ("AWS::Lambda::Function", "has potentially sensitive environment variables"): get_lambda_sensitive_env_vars_guidance,
    ("AWS::Lambda::Function", "may be invokable by unauthorized principals"): get_lambda_unauthorized_invocation_guidance,
    
    # Existing mappings, ensure keywords are still relevant or update if analyzer changes
    ("AWS::Lambda::Function", "function url allows unauthenticated access"): get_lambda_public_url_no_auth_guidance, # Assumes a finding title with this phrase
    ("AWS::Lambda::Function", "active tracing is not enabled"): get_lambda_tracing_guidance, # Assumes a finding title with this phrase
    ("AWS::Lambda::Function", "dlq is not configured"): get_lambda_dlq_guidance, # Assumes a finding title with this phrase
    ("AWS::Lambda::Function", "reserved concurrency not configured"): get_lambda_reserved_concurrency_guidance, # Assumes a finding title with this phrase
    ("AWS::Lambda::Function", "uses outdated runtime"): get_lambda_latest_runtime_guidance, # Assumes a finding title with this phrase
} 