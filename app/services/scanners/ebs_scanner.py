import traceback
import json
from typing import List, Dict, Any

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags

def scan_ebs(aws_provider: AwsProvider, region: str) -> List[Dict[str, Any]]:
    """Scan EBS Volumes and Regional EBS settings."""
    ec2_client = aws_provider.get_client("ec2", region=region)
    resources = []
    account_id = aws_provider.account_id

    try:
        # 1. Scan EBS Volumes (check encryption)
        logger.debug(f"Scanning EBS Volumes in {region} for account {account_id}...")
        volume_count = 0
        paginator = ec2_client.get_paginator('describe_volumes')
        for page in paginator.paginate():
            for volume in page.get('Volumes', []):
                vol_id = volume['VolumeId']
                arn = f"arn:aws:ec2:{region}:{account_id}:volume/{vol_id}"
                tags = format_tags(volume.get('Tags', []))
                # Extract attached instance ID for relationship
                attached_instance_id = None
                if volume.get('Attachments'):
                    # Assuming only one attachment for simplicity
                    attached_instance_id = volume['Attachments'][0].get('InstanceId')

                resources.append({
                    'arn': arn,
                    'resource_id': vol_id,
                    'resource_type': 'EBSVolume',
                    'region': region,
                    'account_id': account_id,
                    'properties': {
                        'VolumeId': vol_id,
                        'Encrypted': volume.get('Encrypted'),
                        'Size': volume.get('Size'),
                        'State': volume.get('State'),
                        'VolumeType': volume.get('VolumeType'),
                        'AvailabilityZone': volume.get('AvailabilityZone'),
                        'KmsKeyId': volume.get('KmsKeyId')
                    },
                    'relationships': {
                        'attached_instance_id': attached_instance_id,
                        'tags': tags
                    }
                })
                volume_count += 1
        logger.debug(f"Found {volume_count} EBS Volumes in {region}.")

        # 2. Check Regional EBS Encryption Default
        logger.debug(f"Checking default EBS encryption in {region} for account {account_id}...")
        try:
            encryption_default = ec2_client.get_ebs_encryption_by_default()
            # Add this as a property to a placeholder 'RegionSettings' resource for now
            # The graph builder can decide whether to merge this into the :Region node
            resources.append({
                # Use a composite ID to make it unique per region/account
                'resource_id': f"{account_id}-{region}-RegionSettings",
                'resource_type': 'RegionSettings', # Placeholder type
                'region': region,
                'account_id': account_id,
                'properties': {
                    'EbsEncryptionByDefault': encryption_default.get('EbsEncryptionByDefault')
                },
                'relationships': {}
            })
            logger.debug(f"Default EBS encryption enabled in {region}: {encryption_default.get('EbsEncryptionByDefault')}")
        except Exception as ebs_default_e:
            logger.error(f"Could not get default EBS encryption status in {region}: {ebs_default_e}")
            # Add error info if needed
            resources.append({
                'resource_id': f"{account_id}-{region}-RegionSettingsError",
                'resource_type': 'Error', 
                'region': region,
                'account_id': account_id,
                'properties': {
                    'Service': 'EC2',
                    'Operation': 'get_ebs_encryption_by_default',
                    'Error': str(ebs_default_e)
                },
                'relationships': {}
            })

    except Exception as e:
        logger.error(f"Error scanning EBS resources in {region} for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())

    return resources 