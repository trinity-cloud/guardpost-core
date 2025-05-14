import traceback
import json # For potential JSON serialization if needed later
from typing import List, Dict, Any

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags # Assuming a util function exists

def scan_ec2(aws_provider: AwsProvider, region: str) -> List[Dict[str, Any]]:
    """Scan EC2 Instances and collect relationship data in a specific region."""
    ec2_client = aws_provider.get_client("ec2", region=region)
    resources = []
    account_id = aws_provider.account_id

    try:
        # Scan Instances (get MetadataOptions, Relationship Data, Tags)
        logger.debug(f"Scanning EC2 Instances in {region} for account {account_id}...")
        instance_count = 0
        paginator = ec2_client.get_paginator('describe_instances')
        instance_reservations = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopped', 'stopping']}])

        for page in instance_reservations:
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
                    tags = format_tags(instance.get('Tags', [])) # Use utility function

                    # --- Extract Relationship Data ---
                    subnet_id = instance.get('SubnetId')
                    vpc_id = instance.get('VpcId')
                    instance_profile = instance.get('IamInstanceProfile')
                    iam_role_arn = instance_profile.get('Arn') if instance_profile else None
                    # Adjust ARN format if needed (Instance Profile ARN vs Role ARN)
                    if iam_role_arn and ':instance-profile/' in iam_role_arn:
                        # Attempt to construct role ARN from instance profile ARN
                        # Format: arn:aws:iam::{account_id}:instance-profile/{profile_name}
                        # Target: arn:aws:iam::{account_id}:role/{role_name}
                        # This usually requires assuming profile name == role name, which is common but not guaranteed.
                        # A get_instance_profile call might be needed for certainty, but adds API calls.
                        profile_name = iam_role_arn.split('/')[-1]
                        iam_role_arn = f"arn:aws:iam::{account_id}:role/{profile_name}"
                        logger.trace(f"Constructed potential Role ARN {iam_role_arn} from profile {instance_profile.get('Arn')}")
                    
                    security_group_ids = [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
                    # --- End Relationship Data ---

                    # Define metadata_options dict beforehand
                    metadata_options_dict = instance.get('MetadataOptions', {})

                    instance_info = {
                        'arn': arn,
                        'resource_id': instance_id,
                        'resource_type': 'Ec2Instance',
                        'region': region,
                        'account_id': account_id,
                        'properties': {
                            'InstanceId': instance_id,
                            'State': instance.get('State', {}).get('Name'),
                            'ImageId': instance.get('ImageId'),
                            'InstanceType': instance.get('InstanceType'),
                            'LaunchTime': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
                            'PrivateIpAddress': instance.get('PrivateIpAddress'),
                            'PublicIpAddress': instance.get('PublicIpAddress'),
                            'SubnetId': subnet_id, # Also keep in properties for easy access
                            'VpcId': vpc_id, # Also keep in properties
                            'IamInstanceProfileArn': instance_profile.get('Arn') if instance_profile else None,

                            # Add specific MetadataOptions fields
                            'MetadataOptions_State': metadata_options_dict.get('State'),
                            'MetadataOptions_HttpTokens': metadata_options_dict.get('HttpTokens'),
                            'MetadataOptions_HttpPutResponseHopLimit': metadata_options_dict.get('HttpPutResponseHopLimit'),
                            # Store original JSON too
                            'MetadataOptionsJson': json.dumps(metadata_options_dict) if metadata_options_dict else None,

                            # 'MetadataOptions': json.dumps(instance.get('MetadataOptions', {})) if instance.get('MetadataOptions') else None, # Old key removed
                        },
                        'relationships': {
                            'subnet_id': subnet_id,
                            'vpc_id': vpc_id,
                            'iam_role_arn': iam_role_arn, # Use the potentially constructed Role ARN
                            'security_group_ids': security_group_ids,
                            'tags': tags # Add tags here
                        }
                    }
                    resources.append(instance_info)
                    instance_count += 1
        logger.debug(f"Found {instance_count} EC2 Instances in {region} for account {account_id}.")

        # ----- Placeholder for other EC2 resource scanning if needed -----
        # Example: Scan EBS Volumes (if they become separate nodes later)
        # logger.debug(f"Scanning EBS Volumes in {region}...")

        # Example: Check Regional EBS Encryption Default (might be Account/Region node property)
        # logger.debug(f"Checking default EBS encryption in {region}...")
        # try:
        #     encryption_default = ec2_client.get_ebs_encryption_by_default()
        #     # Decide where this info fits best - maybe a Region node property?
        #     # resources.append({'resource_type': 'RegionSettings', ...})
        # except Exception as ebs_default_e:
        #     logger.error(f"Could not get default EBS encryption status in {region}: {ebs_default_e}")

    except Exception as e:
        logger.error(f"Error scanning EC2 in {region} for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())
        # Append error information if needed for reporting?
        # resources.append({'Type': 'Error', 'Details': {'Service': 'EC2', 'Region': region, 'Error': str(e)}})

    return resources 