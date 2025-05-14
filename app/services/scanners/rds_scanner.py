import traceback
import json # Potentially needed for complex fields
from typing import List, Dict, Any

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags

def scan_rds(aws_provider: AwsProvider, region: str) -> List[Dict[str, Any]]:
    """Scan RDS DB instances in a specific region and format for graph builder."""
    rds_client = aws_provider.get_client("rds", region=region)
    resources = []
    account_id = aws_provider.account_id
    instance_count = 0

    try:
        logger.debug(f"Scanning RDS DB Instances in {region} for account {account_id}...")
        paginator = rds_client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
             for instance in page.get('DBInstances', []):
                instance_id = instance['DBInstanceIdentifier'] # Use as resource_id
                instance_arn = instance['DBInstanceArn'] # Use as arn
                
                # Extract properties
                endpoint = instance.get('Endpoint', {})
                db_subnet_group = instance.get('DBSubnetGroup', {})
                pending_modified_values = instance.get('PendingModifiedValues', {})
                tags = format_tags(instance.get('TagList', [])) # Get tags

                properties = {
                    'DBInstanceIdentifier': instance_id,
                    'DBInstanceClass': instance.get('DBInstanceClass'),
                    'Engine': instance.get('Engine'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus'),
                    'MasterUsername': instance.get('MasterUsername'),
                    'DBName': instance.get('DBName'),
                    'EndpointAddress': endpoint.get('Address'),
                    'EndpointPort': endpoint.get('Port'),
                    'AllocatedStorage': instance.get('AllocatedStorage'),
                    'InstanceCreateTime': instance.get('InstanceCreateTime').isoformat() if instance.get('InstanceCreateTime') else None,
                    'PreferredBackupWindow': instance.get('PreferredBackupWindow'),
                    'BackupRetentionPeriod': instance.get('BackupRetentionPeriod'),
                    'DBSecurityGroups': json.dumps(instance.get('DBSecurityGroups', [])), # Old style, might be empty
                    'VpcSecurityGroups': json.dumps(instance.get('VpcSecurityGroups', [])), # Store as JSON
                    'DBParameterGroups': json.dumps(instance.get('DBParameterGroups', [])),
                    'AvailabilityZone': instance.get('AvailabilityZone'),
                    'DBSubnetGroupName': db_subnet_group.get('DBSubnetGroupName'),
                    'DBSubnetGroupVpcId': db_subnet_group.get('VpcId'),
                    'DBSubnetGroupStatus': db_subnet_group.get('SubnetGroupStatus'),
                    'Subnets': json.dumps(db_subnet_group.get('Subnets', [])), # Store subnets info
                    'PreferredMaintenanceWindow': instance.get('PreferredMaintenanceWindow'),
                    'PendingModifiedValues': json.dumps(pending_modified_values), # Store as JSON
                    'LatestRestorableTime': instance.get('LatestRestorableTime').isoformat() if instance.get('LatestRestorableTime') else None,
                    'MultiAZ': instance.get('MultiAZ'),
                    'PubliclyAccessible': instance.get('PubliclyAccessible'),
                    'StorageType': instance.get('StorageType'),
                    'DbInstancePort': instance.get('DbInstancePort'),
                    'StorageEncrypted': instance.get('StorageEncrypted'),
                    'KmsKeyId': instance.get('KmsKeyId'),
                    'DbiResourceId': instance.get('DbiResourceId'),
                    'CACertificateIdentifier': instance.get('CACertificateIdentifier'),
                    'CopyTagsToSnapshot': instance.get('CopyTagsToSnapshot'),
                    'DeletionProtection': instance.get('DeletionProtection'),
                    'IAMDatabaseAuthenticationEnabled': instance.get('IAMDatabaseAuthenticationEnabled'),
                    'PerformanceInsightsEnabled': instance.get('PerformanceInsightsEnabled'),
                    'PerformanceInsightsKMSKeyId': instance.get('PerformanceInsightsKMSKeyId'),
                    'PerformanceInsightsRetentionPeriod': instance.get('PerformanceInsightsRetentionPeriod'),
                    'EnhancedMonitoringResourceArn': instance.get('EnhancedMonitoringResourceArn'),
                    'MonitoringInterval': instance.get('MonitoringInterval'),
                    'MonitoringRoleArn': instance.get('MonitoringRoleArn'),
                    'AutoMinorVersionUpgrade': instance.get('AutoMinorVersionUpgrade'),
                    'EnabledCloudwatchLogsExports': instance.get('EnabledCloudwatchLogsExports', [])
                }

                # Extract relationships
                security_group_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', []) if sg.get('VpcSecurityGroupId')]
                # Also consider old DB Security Groups if needed
                db_security_groups = [sg['DBSecurityGroupName'] for sg in instance.get('DBSecurityGroups', []) if sg.get('DBSecurityGroupName')]
                
                relationships = {
                    'vpc_id': db_subnet_group.get('VpcId'),
                    'db_subnet_group_name': db_subnet_group.get('DBSubnetGroupName'),
                    'security_group_ids': security_group_ids,
                    'db_security_group_names': db_security_groups,
                    'monitoring_role_arn': instance.get('MonitoringRoleArn'),
                    'tags': tags
                }

                resources.append({
                    'arn': instance_arn,
                    'resource_id': instance_id,
                    'resource_type': 'DbInstance', # Use consistent type
                    'region': region,
                    'account_id': account_id,
                    'properties': {k: v for k, v in properties.items() if v is not None}, # Filter out None values for cleaner properties
                    'relationships': relationships
                })
                instance_count += 1
        logger.debug(f"Found {instance_count} RDS DB Instances in {region}.")

        # --- Scan DB Subnet Groups ---
        logger.debug(f"Scanning DB Subnet Groups in {region}...")
        subnet_group_count = 0
        try:
            paginator_sg = rds_client.get_paginator('describe_db_subnet_groups')
            for page_sg in paginator_sg.paginate():
                for subnet_group in page_sg.get('DBSubnetGroups', []):
                    sg_name = subnet_group.get('DBSubnetGroupName')
                    if not sg_name: continue

                    # Use Name as resource_id, construct pseudo-ARN
                    sg_arn = f"arn:aws:rds:{region}:{account_id}:subgrp:{sg_name}"
                    vpc_id = subnet_group.get('VpcId')
                    subnet_ids = [s.get('SubnetIdentifier') for s in subnet_group.get('Subnets', []) if s.get('SubnetIdentifier')]
                    # Fetch tags for subnet group (requires separate call if needed, not done here for simplicity)
                    # Example: tags_response = rds_client.list_tags_for_resource(ResourceName=subnet_group['DBSubnetGroupArn'])
                    # tags = format_tags(tags_response.get('TagList', []))
                    tags = {} # Placeholder for tags if needed later

                    resources.append({
                        'arn': sg_arn,
                        'resource_id': sg_name,
                        'resource_type': 'DbSubnetGroup',
                        'region': region,
                        'account_id': account_id,
                        'properties': {
                            'DBSubnetGroupName': sg_name,
                            'DBSubnetGroupDescription': subnet_group.get('DBSubnetGroupDescription'),
                            'VpcId': vpc_id,
                            'SubnetGroupStatus': subnet_group.get('SubnetGroupStatus'),
                            # Store Subnet details as JSON for now, or could create relationships
                            'SubnetsJson': json.dumps(subnet_group.get('Subnets', []))
                        },
                        'relationships': {
                            'vpc_id': vpc_id,
                            'subnet_ids': subnet_ids,
                            'tags': tags # Add tags if fetched
                        }
                    })
                    subnet_group_count += 1
            logger.debug(f"Found {subnet_group_count} DB Subnet Groups in {region}.")
        except Exception as sg_e:
            logger.error(f"Error scanning DB Subnet Groups in {region}: {sg_e}")
        # --- End DB Subnet Group Scan ---

        # TODO: Scan DB Security Groups (Classic), Parameter Groups, Option Groups, Snapshots, Clusters as separate nodes if needed

    except Exception as e:
        logger.error(f"Error scanning RDS in {region} for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())

    return resources 