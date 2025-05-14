import traceback
import json # For serializing complex properties like rules
import hashlib # For generating unique IDs for rules
from typing import List, Dict, Any

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags

def _generate_rule_id(sg_id: str, rule_type: str, permission: Dict[str, Any], source_identifier: str, source_type: str) -> str:
    """Generates a unique ID for a security group rule."""
    hasher = hashlib.md5()
    # Use a consistent set of identifying fields for the hash
    identity_string = f"{sg_id}-{rule_type}-{permission.get('IpProtocol', 'any')}-{permission.get('FromPort', 'any')}-{permission.get('ToPort', 'any')}-{source_type}-{source_identifier}"
    hasher.update(identity_string.encode('utf-8'))
    return hasher.hexdigest()

def _process_ip_permissions(
    sg_id: str, 
    permissions: List[Dict[str, Any]], 
    rule_type: str, # "ingress" or "egress"
    account_id: str, 
    region: str
) -> List[Dict[str, Any]]:
    """Processes IP permissions into individual SecurityGroupRule resources."""
    rule_resources = []
    for perm in permissions:
        ip_protocol = perm.get('IpProtocol', '-1') # AWS uses -1 for all protocols
        from_port = perm.get('FromPort')
        to_port = perm.get('ToPort')

        for ip_range in perm.get('IpRanges', []):
            cidr_ip = ip_range.get('CidrIp')
            if not cidr_ip: continue
            rule_id = _generate_rule_id(sg_id, rule_type, perm, cidr_ip, 'CidrIp')
            arn = f"arn:aws:ec2:{region}:{account_id}:security-group-rule/{sg_id}/{rule_id}" # Construct a pseudo-ARN
            rule_resources.append({
                'arn': arn,
                'resource_id': rule_id,
                'resource_type': 'SecurityGroupRule',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'RuleType': rule_type,
                    'IsEgress': rule_type == 'egress', # Keep IsEgress for boolean check, RuleType for string type
                    'IpProtocol': ip_protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'CidrIpv4': cidr_ip,
                    'Description': ip_range.get('Description')
                },
                'relationships': {
                    'parent_security_group_id': sg_id
                }
            })

        for ipv6_range in perm.get('Ipv6Ranges', []):
            cidr_ipv6 = ipv6_range.get('CidrIpv6')
            if not cidr_ipv6: continue
            rule_id = _generate_rule_id(sg_id, rule_type, perm, cidr_ipv6, 'CidrIpv6')
            arn = f"arn:aws:ec2:{region}:{account_id}:security-group-rule/{sg_id}/{rule_id}"
            rule_resources.append({
                'arn': arn,
                'resource_id': rule_id,
                'resource_type': 'SecurityGroupRule',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'RuleType': rule_type,
                    'IsEgress': rule_type == 'egress',
                    'IpProtocol': ip_protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'CidrIpv6': cidr_ipv6,
                    'Description': ipv6_range.get('Description')
                },
                'relationships': {
                    'parent_security_group_id': sg_id
                }
            })

        for user_group_pair in perm.get('UserIdGroupPairs', []):
            source_sg_id = user_group_pair.get('GroupId')
            if not source_sg_id: continue
            rule_id = _generate_rule_id(sg_id, rule_type, perm, source_sg_id, 'UserIdGroupPair')
            arn = f"arn:aws:ec2:{region}:{account_id}:security-group-rule/{sg_id}/{rule_id}"
            rule_resources.append({
                'arn': arn,
                'resource_id': rule_id,
                'resource_type': 'SecurityGroupRule',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'RuleType': rule_type,
                    'IsEgress': rule_type == 'egress',
                    'IpProtocol': ip_protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'SourceSecurityGroupId': source_sg_id,
                    'SourceSecurityGroupOwnerId': user_group_pair.get('UserId'),
                    'Description': user_group_pair.get('Description')
                },
                'relationships': {
                    'parent_security_group_id': sg_id,
                    'source_security_group_id': source_sg_id # For graph builder to link if needed
                }
            })

        for prefix_list_id_obj in perm.get('PrefixListIds', []):
            prefix_list_id = prefix_list_id_obj.get('PrefixListId')
            if not prefix_list_id: continue
            rule_id = _generate_rule_id(sg_id, rule_type, perm, prefix_list_id, 'PrefixListId')
            arn = f"arn:aws:ec2:{region}:{account_id}:security-group-rule/{sg_id}/{rule_id}"
            rule_resources.append({
                'arn': arn,
                'resource_id': rule_id,
                'resource_type': 'SecurityGroupRule',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'RuleType': rule_type,
                    'IsEgress': rule_type == 'egress',
                    'IpProtocol': ip_protocol,
                    'FromPort': from_port,
                    'ToPort': to_port,
                    'SourcePrefixListId': prefix_list_id,
                    'Description': prefix_list_id_obj.get('Description')
                },
                'relationships': {
                    'parent_security_group_id': sg_id
                    # 'source_prefix_list_id': prefix_list_id # For graph builder if needed
                }
            })
    return rule_resources

def scan_vpc(aws_provider: AwsProvider, region: str) -> List[Dict[str, Any]]:
    """Scan VPC resources: VPCs, Subnets, Route Tables, IGWs, NAT GWs, Security Groups and their Rules."""
    ec2_client = aws_provider.get_client("ec2", region=region)
    resources = []
    account_id = aws_provider.account_id

    try:
        # 1. Scan VPCs
        logger.debug(f"Scanning VPCs in {region} for account {account_id}...")
        vpcs = ec2_client.describe_vpcs().get('Vpcs', [])
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            arn = f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
            tags = format_tags(vpc.get('Tags', []))
            resources.append({
                'arn': arn,
                'resource_id': vpc_id,
                'resource_type': 'Vpc',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'VpcId': vpc_id,
                    'CidrBlock': vpc.get('CidrBlock'),
                    'IsDefault': vpc.get('IsDefault'),
                    'State': vpc.get('State'),
                    'InstanceTenancy': vpc.get('InstanceTenancy')
                },
                'relationships': {
                    'tags': tags
                }
            })
        logger.debug(f"Found {len(vpcs)} VPCs in {region}.")

        # 2. Scan Subnets
        logger.debug(f"Scanning Subnets in {region}...")
        subnets = ec2_client.describe_subnets().get('Subnets', [])
        for subnet in subnets:
            subnet_id = subnet['SubnetId']
            vpc_id = subnet['VpcId']
            arn = f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}"
            tags = format_tags(subnet.get('Tags', []))
            resources.append({
                'arn': arn,
                'resource_id': subnet_id,
                'resource_type': 'Subnet',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'SubnetId': subnet_id,
                    'VpcId': vpc_id,
                    'CidrBlock': subnet.get('CidrBlock'),
                    'AvailabilityZone': subnet.get('AvailabilityZone'),
                    'AvailabilityZoneId': subnet.get('AvailabilityZoneId'),
                    'MapPublicIpOnLaunch': subnet.get('MapPublicIpOnLaunch'),
                    'State': subnet.get('State'),
                },
                'relationships': {
                    'vpc_id': vpc_id,
                    'tags': tags
                }
            })
        logger.debug(f"Found {len(subnets)} Subnets in {region}.")

        # 3. Scan Route Tables
        logger.debug(f"Scanning Route Tables in {region}...")
        route_tables = ec2_client.describe_route_tables().get('RouteTables', [])
        for rt in route_tables:
            rt_id = rt['RouteTableId']
            vpc_id = rt['VpcId']
            arn = f"arn:aws:ec2:{region}:{account_id}:route-table/{rt_id}"
            tags = format_tags(rt.get('Tags', []))
            # Process routes to identify targets
            routes = []
            for route in rt.get('Routes', []):
                target_type = None
                target_id = None
                if route.get('GatewayId'):
                    target_id = route['GatewayId']
                    target_type = 'InternetGateway' if 'igw-' in target_id else 'VPCEndpoint' # Simple assumption
                elif route.get('NatGatewayId'):
                    target_id = route['NatGatewayId']
                    target_type = 'NatGateway'
                elif route.get('TransitGatewayId'):
                    target_id = route['TransitGatewayId']
                    target_type = 'TransitGateway'
                elif route.get('NetworkInterfaceId'):
                    target_id = route['NetworkInterfaceId']
                    target_type = 'NetworkInterface'
                elif route.get('InstanceId'):
                    target_id = route['InstanceId']
                    target_type = 'Instance' # Route to specific instance
                elif route.get('VpcPeeringConnectionId'):
                     target_id = route['VpcPeeringConnectionId']
                     target_type = 'VpcPeeringConnection'

                routes.append({
                    'DestinationCidrBlock': route.get('DestinationCidrBlock'),
                    'DestinationPrefixListId': route.get('DestinationPrefixListId'),
                    'TargetType': target_type,
                    'TargetId': target_id,
                    'State': route.get('State'),
                    'Origin': route.get('Origin')
                })
            
            # Process associations to find main table and associated subnets
            associated_subnet_ids = []
            is_main = False
            for assoc in rt.get('Associations', []):
                if assoc.get('Main') is True:
                    is_main = True
                if assoc.get('SubnetId'):
                    associated_subnet_ids.append(assoc['SubnetId'])

            resources.append({
                'arn': arn,
                'resource_id': rt_id,
                'resource_type': 'RouteTable',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'RouteTableId': rt_id,
                    'VpcId': vpc_id,
                    'IsMain': is_main,
                    'Routes': json.dumps(routes) # Store complex routes as JSON string
                },
                'relationships': {
                    'vpc_id': vpc_id,
                    'associated_subnet_ids': associated_subnet_ids,
                    # Target IDs from routes can be used to build ROUTES_TO relationships later
                    'routes_targets': [{'destination': r.get('DestinationCidrBlock'), 'target_id': r.get('TargetId'), 'target_type': r.get('TargetType')} for r in routes if r.get('TargetId')],
                    'tags': tags
                }
            })
        logger.debug(f"Found {len(route_tables)} Route Tables in {region}.")

        # 4. Scan Internet Gateways
        logger.debug(f"Scanning Internet Gateways in {region}...")
        igws = ec2_client.describe_internet_gateways().get('InternetGateways', [])
        for igw in igws:
            igw_id = igw['InternetGatewayId']
            tags = format_tags(igw.get('Tags', []))
            attached_vpc_id = None
            if igw.get('Attachments'):
                # Assuming only one attachment
                attached_vpc_id = igw['Attachments'][0].get('VpcId')
            arn = f"arn:aws:ec2:{region}:{account_id}:internet-gateway/{igw_id}"
            resources.append({
                'arn': arn,
                'resource_id': igw_id,
                'resource_type': 'InternetGateway',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'InternetGatewayId': igw_id,
                    'Attachments': json.dumps(igw.get('Attachments', [])) # Dump to JSON string
                },
                'relationships': {
                    'attached_vpc_id': attached_vpc_id,
                    'tags': tags
                }
            })
        logger.debug(f"Found {len(igws)} Internet Gateways in {region}.")

        # 5. Scan NAT Gateways
        logger.debug(f"Scanning NAT Gateways in {region}...")
        nat_gws = ec2_client.describe_nat_gateways().get('NatGateways', [])
        for nat in nat_gws:
            nat_id = nat['NatGatewayId']
            vpc_id = nat['VpcId']
            subnet_id = nat['SubnetId']
            arn = f"arn:aws:ec2:{region}:{account_id}:natgateway/{nat_id}"
            tags = format_tags(nat.get('Tags', []))
            resources.append({
                'arn': arn,
                'resource_id': nat_id,
                'resource_type': 'NatGateway',
                'region': region,
                'account_id': account_id,
                'properties': {
                    'NatGatewayId': nat_id,
                    'VpcId': vpc_id,
                    'SubnetId': subnet_id,
                    'State': nat.get('State'),
                    'ConnectivityType': nat.get('ConnectivityType'),
                    'NatGatewayAddresses': nat.get('NatGatewayAddresses')
                },
                'relationships': {
                    'vpc_id': vpc_id,
                    'subnet_id': subnet_id,
                    'tags': tags
                }
            })
        logger.debug(f"Found {len(nat_gws)} NAT Gateways in {region}.")

        # 6. Scan Security Groups (logic moved from scan_ec2)
        logger.debug(f"Scanning Security Groups in {region}...")
        sg_count = 0
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
             for sg in page.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                vpc_id = sg.get('VpcId') # SGs can be EC2-Classic (no VPC), handle this?
                arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"
                tags = format_tags(sg.get('Tags', []))
                resources.append({
                    'arn': arn,
                    'resource_id': sg_id,
                    'resource_type': 'SecurityGroup',
                    'region': region,
                    'account_id': account_id,
                    'properties': {
                        'GroupId': sg_id,
                        'GroupName': sg.get('GroupName'),
                        'Description': sg.get('Description'),
                        'VpcId': vpc_id,
                        'OwnerId': sg.get('OwnerId'), # Adding OwnerId as it's available
                        # IpPermissions and IpPermissionsEgress are now processed into separate rule nodes
                    },
                    'relationships': {
                        'vpc_id': vpc_id,
                        'tags': tags
                        # APPLIES_TO relationship built later from EC2/Lambda/RDS data
                    }
                })
                sg_count += 1
                
                # Process Ingress Rules
                ingress_permissions = sg.get('IpPermissions', [])
                ingress_rules = _process_ip_permissions(sg_id, ingress_permissions, 'ingress', account_id, region)
                resources.extend(ingress_rules)
                
                # Process Egress Rules
                egress_permissions = sg.get('IpPermissionsEgress', [])
                egress_rules = _process_ip_permissions(sg_id, egress_permissions, 'egress', account_id, region)
                resources.extend(egress_rules)

        logger.debug(f"Found {sg_count} Security Groups in {region} and their associated rules.")

    except Exception as e:
        logger.error(f"Error scanning VPC resources in {region} for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())
        # Optionally append detailed error info

    return resources 