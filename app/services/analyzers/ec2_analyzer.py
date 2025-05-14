# Placeholder for ec2 analyzer logic 

import uuid
import datetime
from typing import Dict, List, Optional, Any, Callable
import traceback
import json # For parsing policy documents (if needed in future EC2 checks)

from loguru import logger
from sqlalchemy.orm import Session

# Assuming schemas and models are accessible via absolute import paths
from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding # Pydantic schema
from app.db import models # DB Model
from app.db.graph_db import Neo4jClient # Import Neo4j Client
from .graph_queries import ec2_graph_queries # Import the new graph query module

# Removed the class context, this is now a standalone function
def analyze_ec2(
    db: Session,
    db_client: Neo4jClient, 
    account_id: str, 
    scan_id: uuid.UUID, 
    region: str, 
    ec2_resources: List[Dict[str, Any]],
    create_finding_callback: Callable[..., models.Finding] # Callback function
) -> int:
    """Analyze collected EC2 resources and save findings to DB."""
    findings_created = 0
    scan_id_str = str(scan_id)
    logger.info(f"[{scan_id_str}] Starting EC2 analysis for account {account_id} in region {region} using graph data.")

    # Check 1: Instance Exposed to Internet on Sensitive Port (Using Graph Query)
    try:
        # Define sensitive ports or pass as param if configurable later
        sensitive_ports_to_check = [22, 3389, 3306, 1433, 5432, 27017, 1521, 6379]
        exposed_instances = ec2_graph_queries.check_internet_exposed_instances(
            db_client, account_id, region, scan_id_str, sensitive_ports=sensitive_ports_to_check
        )
        for data in exposed_instances:
            instance_id = data.get('InstanceId')
            instance_arn = data.get('InstanceArn')
            sg_id = data.get('SecurityGroupId')
            sg_name = data.get('SecurityGroupName')
            port = data.get('PortOpened') # Assuming this logic is sufficient, or use FromPort/ToPort
            rule_desc = data.get('RuleDescription', 'N/A')
            service_name_map = {22: "SSH", 3389: "RDP", 3306: "MySQL", 1433:"MSSQL", 5432:"PostgreSQL", 27017:"MongoDB", 1521:"Oracle", 6379:"Redis"}
            service_name = service_name_map.get(port, f"Port {port}")
            
            details_for_finding = {
                "instance_id": instance_id,
                "security_group_id": sg_id,
                "security_group_name": sg_name,
                "port_opened": port,
                "service_name": service_name,
                "rule_description": rule_desc
            }
            create_finding_callback(
                db=db, 
                account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, # Use Instance ARN for finding
                resource_type="AWS::EC2::Instance",
                title=f"EC2 instance '{instance_id}' has sensitive port {service_name} exposed to the internet",
                description=f"Instance '{instance_id}' is exposed to 0.0.0.0/0 on port {port} ({service_name}) via Security Group '{sg_name}' ({sg_id}). Rule: {rule_desc}",
                severity=FindingSeverity.HIGH, category=FindingCategory.PUBLIC_EXPOSURE,
                compliance_standards=["CIS AWS Benchmark 4.1", "CIS AWS Benchmark 4.2"], # Adjust as needed
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] EC2 Internet Exposed check completed. Found {len(exposed_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during EC2 Internet Exposed analysis: {e}")
        logger.error(traceback.format_exc())

    # TODO: Refactor other EC2 checks (Unrestricted Egress, Default SG, IMDSv2) to use graph queries
    # For now, keep the existing logic that uses ec2_resources list for those.

    # --- Existing EC2 Checks (to be refactored or confirmed if still needed) ---
    security_groups = [r for r in ec2_resources if r.get('Type') == 'SecurityGroup']
    instances = [r for r in ec2_resources if r.get('Type') == 'EC2Instance']
    volumes = [r for r in ec2_resources if r.get('Type') == 'EBSVolume']
    regional_settings = next((r['Details'] for r in ec2_resources if r.get('Type') == 'EC2RegionalSettings'), None)

    # --- EC2 Security Group Checks (PRD 2.2.4, CIS 4.x) --- 
    unrestricted_ports = {22: "SSH", 3389: "RDP"} # Add more sensitive ports like DB ports if needed

    for sg_resource in security_groups:
        sg = sg_resource.get('Details', {})
        sg_id = sg.get('GroupId')
        sg_name = sg.get('GroupName')
        if not sg_id: continue

        # Check 1: ingress rules for unrestricted access to sensitive ports (CIS 4.1, 4.2)
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_protocol = rule.get('IpProtocol', '').lower()

            # Check ranges within the rule
            has_unrestricted_ipv4 = any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))
            has_unrestricted_ipv6 = any(ip_range.get('CidrIpv6') == '::/0' for ip_range in rule.get('Ipv6Ranges', []))
            is_unrestricted = has_unrestricted_ipv4 or has_unrestricted_ipv6

            if is_unrestricted:
                # Check if the rule applies to any sensitive port
                for port, service_name in unrestricted_ports.items():
                    # Check if the port falls within the rule's range (handle 'all traffic' case)
                    port_matches = False
                    if ip_protocol == '-1': # All traffic
                        port_matches = True
                    elif from_port is not None and to_port is not None:
                         if from_port <= port <= to_port:
                             port_matches = True
                    # Add specific protocol checks if needed (e.g., ip_protocol == 'tcp')
                    
                    if port_matches:
                         details_for_finding = {
                             "security_group_id": sg_id,
                             "security_group_name": sg_name,
                             "port": port,
                             "service_name": service_name,
                             "rule_details": rule # Pass the whole rule for context in guidance
                         }
                         create_finding_callback( # Use callback
                             db=db, 
                             account_id=account_id, scan_id=scan_id, region=region,
                             resource_id=sg_id, resource_type="AWS::EC2::SecurityGroup",
                             title=f"Security group '{sg_name}' ({sg_id}) allows unrestricted {service_name} access",
                             description=f"The security group allows unrestricted ingress (from 0.0.0.0/0 or ::/0) to port {port} ({service_name}).",
                             severity=FindingSeverity.HIGH, category=FindingCategory.NETWORK,
                             compliance_standards=["CIS AWS Benchmark 4.1", "CIS AWS Benchmark 4.2"],
                             details=details_for_finding
                         )
                         # Avoid creating duplicate findings for the same SG for different unrestricted ports if range covers multiple
                         # This logic could be improved, but is okay for now.
                         findings_created += 1

        # Check 2: Unrestricted Egress (CIS 4.4)
        # NOTE: Default behavior for SG is allow all egress. This check flags explicit allow-all rules if added.
        unrestricted_egress_found = False # Flag to create only one finding per SG
        for rule in sg.get('IpPermissionsEgress', []):
            ip_protocol = rule.get('IpProtocol', '').lower()
            is_all_protocols = ip_protocol == '-1'
            # More precise check for all ports TCP/UDP:
            is_tcp_all = ip_protocol == 'tcp' and rule.get('FromPort') == 0 and rule.get('ToPort') == 65535
            is_udp_all = ip_protocol == 'udp' and rule.get('FromPort') == 0 and rule.get('ToPort') == 65535
            is_all_ports = rule.get('FromPort') is None and rule.get('ToPort') is None and not (is_tcp_all or is_udp_all)
            
            is_wide_open_ports = is_all_protocols or is_tcp_all or is_udp_all or is_all_ports

            has_unrestricted_ipv4 = any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))
            has_unrestricted_ipv6 = any(ip_range.get('CidrIpv6') == '::/0' for ip_range in rule.get('Ipv6Ranges', []))
            is_unrestricted_destination = has_unrestricted_ipv4 or has_unrestricted_ipv6

            if is_unrestricted_destination and is_wide_open_ports and not unrestricted_egress_found:
                details_for_finding = {
                    "security_group_id": sg_id,
                    "security_group_name": sg_name,
                    "rule_details": rule
                }
                create_finding_callback( # Use callback
                    db=db, account_id=account_id, scan_id=scan_id, region=region,
                    resource_id=sg_id, resource_type="AWS::EC2::SecurityGroup",
                    title=f"Security group '{sg_name}' ({sg_id}) allows unrestricted egress traffic",
                    description=f"The security group allows egress traffic to all destinations (0.0.0.0/0 or ::/0) on all or a wide range of protocols/ports. This increases the risk of data exfiltration.",
                    severity=FindingSeverity.MEDIUM, category=FindingCategory.NETWORK,
                    compliance_standards=["CIS AWS Benchmark 4.4"],
                    details=details_for_finding
                )
                findings_created += 1
                unrestricted_egress_found = True # Set flag

        # Check 3: Default Security Group Restrictions (CIS 4.3)
        if sg_name == 'default':
             # Default SG allows all outbound traffic by default, and all traffic between instances in the SG.
             # Check for ANY explicitly added ingress rules (beyond the self-referencing one) or ANY egress rules *other than* the default allow-all.
             # A simpler check: flag if any rules exist other than the potential default egress-all.
             has_non_default_ingress = any(not r.get('UserIdGroupPairs') for r in sg.get('IpPermissions', [])) # Check if any non-self-referencing ingress exists
             # Check if egress is NOT the single default allow-all rule
             egress_rules = sg.get('IpPermissionsEgress', [])
             is_default_egress_only = False
             if len(egress_rules) == 1:
                 rule = egress_rules[0]
                 is_all_proto = rule.get('IpProtocol') == '-1'
                 is_all_dest = any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in rule.get('IpRanges', []))
                 if is_all_proto and is_all_dest and not rule.get('Ipv6Ranges') and not rule.get('PrefixListIds') and not rule.get('UserIdGroupPairs'):
                     is_default_egress_only = True
                     
             if has_non_default_ingress or not is_default_egress_only:
                details_for_finding = {"security_group_id": sg_id, "security_group_name": sg_name, "is_default": True, "ingress_rules": sg.get('IpPermissions', []), "egress_rules": egress_rules}
                create_finding_callback( # Use callback
                    db=db, account_id=account_id, scan_id=scan_id, region=region,
                    resource_id=sg_id, resource_type="AWS::EC2::SecurityGroup",
                    title=f"Default security group '{sg_name}' ({sg_id}) has potentially insecure rules",
                    description=f"The default security group '{sg_name}' should not allow ingress traffic and should only contain the default egress allow-all rule. Custom rules were detected.",
                    severity=FindingSeverity.MEDIUM, category=FindingCategory.NETWORK,
                    compliance_standards=["CIS AWS Benchmark 4.3"],
                    details=details_for_finding
                )
                findings_created += 1

    # Check 4: EBS Encryption by Default (CIS 4.5)
    if regional_settings and 'EbsEncryptionByDefault' in regional_settings:
        if not regional_settings.get('EbsEncryptionByDefault'):
            details_for_finding = {"region": region, "ebs_encryption_by_default_enabled": False, "kms_key_id": regional_settings.get("DefaultKmsKeyId")}
            create_finding_callback( # Use callback
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=f"aws-region-{region}", resource_type="AWS::EC2::RegionalSettings", # Pseudo-resource ID
                title=f"EBS encryption by default is not enabled in region '{region}'",
                description="Enabling EBS encryption by default ensures that all newly created EBS volumes are automatically encrypted.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.ENCRYPTION,
                compliance_standards=["CIS AWS Benchmark 4.5"],
                details=details_for_finding
            )
            findings_created += 1
    elif regional_settings and '_Error_EbsEncryptionByDefault' in regional_settings:
         logger.warning(f"Skipping EBS default encryption check in {region} due to fetch error.")
         
    # Check 5: Unencrypted EBS Volumes (CIS 4.6)
    for volume_resource in volumes:
        volume = volume_resource.get('Details', {})
        volume_id = volume.get('VolumeId')
        if not volume_id: continue
        
        if not volume.get('Encrypted'):
            details_for_finding = {"volume_id": volume_id, "is_encrypted": False, "attachments": volume.get("Attachments", [])}
            create_finding_callback( # Use callback
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=volume_id, resource_type="AWS::EC2::Volume",
                title=f"EBS volume '{volume_id}' is not encrypted",
                description="EBS volumes containing sensitive data should be encrypted at rest.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.ENCRYPTION,
                compliance_standards=["CIS AWS Benchmark 4.6"],
                details=details_for_finding
            )
            findings_created += 1

    # Check 6: IMDSv2 Required (CIS 4.8) - Using Graph Query
    try:
        logger.debug(f"[{scan_id_str}] Checking EC2 Instances for IMDSv2 enforcement...")
        imdsv2_optional_instances = ec2_graph_queries.check_instances_not_enforcing_imdsv2(
            db_client, account_id, region, scan_id_str
        )
        for data in imdsv2_optional_instances:
            instance_id = data.get('InstanceId')
            instance_arn = data.get('InstanceArn')
            http_tokens_status = data.get('HttpTokens', 'optional') # From graph node property
            http_endpoint_status = data.get('HttpEndpoint', 'enabled')
            
            details_for_finding = {
                "instance_id": instance_id,
                "http_tokens": http_tokens_status,
                "http_endpoint": http_endpoint_status,
                "metadata_options": data.get('MetadataOptions') # Pass the full dict if guidance needs more
            }
            create_finding_callback( 
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, # Use ARN for finding resource ID
                resource_type="AWS::EC2::Instance",
                title=f"EC2 instance '{instance_id}' does not require IMDSv2",
                description="The instance metadata service (IMDS) should be configured to require IMDSv2 (HttpTokens=required) to mitigate SSRF vulnerabilities.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.NETWORK, # Changed category to NETWORK
                compliance_standards=["CIS AWS Benchmark 4.8"],
                details=details_for_finding
             )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] IMDSv2 check completed. Found {len(imdsv2_optional_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during IMDSv2 analysis: {e}")
        logger.error(traceback.format_exc())

    logger.info(f"[{scan_id_str}] Completed EC2 analysis for account {account_id} in region {region}. Findings created: {findings_created}")
    return findings_created 