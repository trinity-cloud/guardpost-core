import boto3
import json
import time
import os
import argparse
from dotenv import load_dotenv
from botocore.exceptions import ClientError, WaiterError

# Load .env file to get AWS credentials if not already in environment
load_dotenv()

STATE_FILE = "test_resources_state.json"
DEFAULT_REGION = os.environ.get("AWS_REGION", "us-east-1") # Or your preferred default

# --- Resource Configuration ---
EC2_INSTANCE_TYPE = "t3.nano"
EC2_AMI_ID = None # We will fetch the latest Amazon Linux 2 AMI for the region
EC2_KEY_NAME = "trinity-nano-key" # Assumes this keypair exists in your account/region
EC2_INSTANCE_TAGS = [
    {'Key': 'Name', 'Value': 'guardpost-blast-radius-test-ec2'},
    {'Key': 'GuardPostTestResource', 'Value': 'true'}
]

S3_BUCKET_NAME_PREFIX = "guardpost-blast-radius-test-"
S3_BUCKET_TAGS = [
    {'Key': 'Name', 'Value': 'guardpost-blast-radius-test-s3'},
    {'Key': 'GuardPostTestResource', 'Value': 'true'}
]

RDS_DB_INSTANCE_IDENTIFIER_PREFIX = "guardpost-br-test-db-"
RDS_INSTANCE_CLASS = "db.t3.micro"
RDS_ENGINE = "postgres"
RDS_ENGINE_VERSION = "14" # Check for current supported versions
RDS_ALLOCATED_STORAGE = 20 # GB
RDS_DB_NAME = "guardposttestdb"
RDS_MASTER_USERNAME = "gpadmin"
RDS_MASTER_PASSWORD = "GuardPostTestDBPassword123!" # Store securely or generate
RDS_TAGS = [
    {'Key': 'Name', 'Value': 'guardpost-blast-radius-test-rds'},
    {'Key': 'GuardPostTestResource', 'Value': 'true'}
]
# --- End Resource Configuration ---

def get_latest_amazon_linux_ami(ec2_client):
    """Gets the latest Amazon Linux 2 AMI ID."""
    print("Fetching latest Amazon Linux 2 AMI ID...")
    try:
        response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'virtualization-type', 'Values': ['hvm']}
            ],
            IncludeDeprecated=False
        )
        images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        if images:
            ami_id = images[0]['ImageId']
            print(f"Using AMI ID: {ami_id}")
            return ami_id
        else:
            print("Error: Could not find any Amazon Linux 2 AMIs.")
            return None
    except ClientError as e:
        print(f"Error fetching AMI: {e}")
        return None

def load_state():
    """Loads resource IDs from the state file."""
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state):
    """Saves resource IDs to the state file."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def spin_up_resources(region_name=DEFAULT_REGION):
    """Spins up EC2, S3, and RDS test resources."""
    print(f"--- Starting resource provisioning in region: {region_name} ---")
    state = load_state()
    
    ec2_client = boto3.client('ec2', region_name=region_name)
    s3_client = boto3.client('s3', region_name=region_name)
    rds_client = boto3.client('rds', region_name=region_name)

    # --- 1. S3 Bucket ---
    if not state.get('s3_bucket_name'):
        # Generate a unique bucket name
        timestamp = int(time.time())
        bucket_name = f"{S3_BUCKET_NAME_PREFIX}{timestamp}"
        print(f"Creating S3 bucket: {bucket_name}...")
        try:
            if region_name == "us-east-1":
                s3_client.create_bucket(Bucket=bucket_name)
            else:
                s3_client.create_bucket(
                    Bucket=bucket_name, 
                    CreateBucketConfiguration={'LocationConstraint': region_name}
                )
            # No specific waiter for bucket creation, usually fast.
            print(f"S3 bucket {bucket_name} created (or already exists). Tagging...")
            s3_client.put_bucket_tagging(Bucket=bucket_name, Tagging={'TagSet': S3_BUCKET_TAGS})
            state['s3_bucket_name'] = bucket_name
            state['s3_bucket_region'] = region_name
            save_state(state)
        except ClientError as e:
            if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
                print(f"S3 bucket {bucket_name} already exists and is owned by you.")
                state['s3_bucket_name'] = bucket_name # Assume it's ours if name matches
                state['s3_bucket_region'] = region_name
                save_state(state)
            else:
                print(f"Error creating S3 bucket: {e}")
    else:
        print(f"S3 bucket {state.get('s3_bucket_name')} already exists in state.")

    # --- 2. EC2 Instance ---
    # Requires a KeyPair named EC2_KEY_NAME in the target region.
    # Assumes default VPC and a public subnet for simplicity.
    global EC2_AMI_ID
    if EC2_AMI_ID is None:
        EC2_AMI_ID = get_latest_amazon_linux_ami(ec2_client)
    
    if not EC2_AMI_ID:
        print("Cannot proceed without an AMI ID for EC2 instance.")
        return

    if not state.get('ec2_instance_id'):
        print(f"Creating EC2 instance (type: {EC2_INSTANCE_TYPE}, AMI: {EC2_AMI_ID}, Key: {EC2_KEY_NAME})...")
        try:
            # Find default VPC
            default_vpc_id = None
            vpcs_response = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
            if vpcs_response.get('Vpcs'):
                default_vpc_id = vpcs_response['Vpcs'][0]['VpcId']
                print(f"Using default VPC: {default_vpc_id}")
                state['ec2_default_vpc_id'] = default_vpc_id # Save for RDS if needed
            else:
                print("Error: No default VPC found in this region. EC2/RDS launch may fail.")
                # Allow to proceed, might work if non-default VPC has suitable subnets somehow picked up

            # Find a public subnet in the default VPC (or first available subnet)
            subnet_id = None
            if default_vpc_id:
                subnets_response = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [default_vpc_id]}])
                for subnet in subnets_response.get('Subnets', []):
                    if subnet.get('MapPublicIpOnLaunch') or len(subnets_response.get('Subnets', [])) == 1:
                        subnet_id = subnet['SubnetId']
                        print(f"Using subnet: {subnet_id}")
                        break
                if not subnet_id and subnets_response.get('Subnets'):
                    subnet_id = subnets_response['Subnets'][0]['SubnetId'] # Fallback to first subnet
                    print(f"Warning: Could not find an ideal public subnet, using first available: {subnet_id}")
            
            if not subnet_id:
                 print("Error: No subnet found. Cannot launch EC2 instance.")
                 return

            # Create a unique Security Group for this instance run
            timestamp_sg = int(time.time())
            sg_name = f'guardpost-test-ec2-sg-{timestamp_sg}'
            sg_id = None
            try:
                sg_response = ec2_client.create_security_group(GroupName=sg_name, Description='Test SG for GuardPost EC2', VpcId=default_vpc_id)
                sg_id = sg_response['GroupId']
                ec2_client.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}] # WARNING: Open to all for SSH - for testing only
                    }]
                )
                print(f"Created Security Group {sg_name} ({sg_id}) with SSH access.")
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                    sgs_response = ec2_client.describe_security_groups(GroupNames=[sg_name])
                    sg_id = sgs_response['SecurityGroups'][0]['GroupId']
                    print(f"Security Group {sg_name} ({sg_id}) already exists.")
                else:
                    print(f"Error with Security Group: {e}")
                    # If create failed and it wasn't a duplicate, we can't proceed with this SG.
                    # For simplicity, we'll let it fail if it's not a duplicate, rather than trying to find an existing one.
                    # A more robust script might try to find/reuse a generic one, but this keeps cleanup simple.
                    return
            
            if not sg_id: return

            run_instances_response = ec2_client.run_instances(
                ImageId=EC2_AMI_ID,
                InstanceType=EC2_INSTANCE_TYPE,
                KeyName=EC2_KEY_NAME,
                MinCount=1,
                MaxCount=1,
                TagSpecifications=[{'ResourceType': 'instance', 'Tags': EC2_INSTANCE_TAGS}],
                NetworkInterfaces=[{
                    'DeviceIndex': 0,
                    'SubnetId': subnet_id,
                    'Groups': [sg_id],
                    'AssociatePublicIpAddress': True # For t3.nano in default VPC
                }]
            )
            instance_id = run_instances_response['Instances'][0]['InstanceId']
            print(f"EC2 instance {instance_id} creation initiated. Waiting for it to run...")
            waiter = ec2_client.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])
            print(f"EC2 instance {instance_id} is running.")
            state['ec2_instance_id'] = instance_id
            state['ec2_region'] = region_name
            state['ec2_sg_id'] = sg_id
            save_state(state)
        except ClientError as e:
            print(f"Error creating EC2 instance: {e}")
        except WaiterError as e:
            print(f"Error waiting for EC2 instance: {e}")
    else:
        print(f"EC2 instance {state.get('ec2_instance_id')} already exists in state.")

    # --- 3. RDS Instance ---
    if not state.get('rds_instance_identifier'):
        db_instance_identifier = f"{RDS_DB_INSTANCE_IDENTIFIER_PREFIX}{int(time.time()) % 10000}"
        print(f"Creating RDS instance: {db_instance_identifier} (this may take several minutes)...")
        try:
            # RDS needs DB Subnet Group. Create one if not exists or use default.
            db_subnet_group_name = "guardpost-test-db-subnet-group"
            
            # Ensure we have a default_vpc_id for RDS setup
            default_vpc_id_rds = state.get('ec2_default_vpc_id')
            if not default_vpc_id_rds: # If not in state (e.g. EC2 was skipped or first run)
                vpcs_response_rds = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
                if vpcs_response_rds.get('Vpcs'):
                    default_vpc_id_rds = vpcs_response_rds['Vpcs'][0]['VpcId']
                    logger.info(f"RDS setup: Using discovered default VPC: {default_vpc_id_rds}")
                    state['ec2_default_vpc_id'] = default_vpc_id_rds # Save it if we just found it
                    save_state(state)
                else:
                    print("Error: No default VPC found. Cannot determine subnets for RDS DB Subnet Group.")
                    return
            
            subnet_ids_for_rds = []

            if default_vpc_id_rds:
                subnets_resp = ec2_client.describe_subnets(Filters=[{'Name':'vpc-id', 'Values':[default_vpc_id_rds]}])
                subnet_ids_for_rds = [s['SubnetId'] for s in subnets_resp.get('Subnets', [])]
            
            if len(subnet_ids_for_rds) < 2:
                print(f"Warning: Default VPC does not have enough subnets in different AZs for RDS. Attempting with available: {subnet_ids_for_rds}")
                if not subnet_ids_for_rds:
                    print("Error: No subnets found for RDS. Cannot create DB Subnet Group.")
                    return
            try:
                rds_client.create_db_subnet_group(
                    DBSubnetGroupName=db_subnet_group_name,
                    DBSubnetGroupDescription="Test DB Subnet Group for GuardPost",
                    SubnetIds=subnet_ids_for_rds[:2] if len(subnet_ids_for_rds) >=2 else subnet_ids_for_rds # Use first 2 or 1
                )
                print(f"DB Subnet Group '{db_subnet_group_name}' created.")
            except rds_client.exceptions.DBSubnetGroupAlreadyExistsFault:
                print(f"DB Subnet Group '{db_subnet_group_name}' already exists.")
            except ClientError as e:
                print(f"Error creating DB Subnet Group: {e}")
                # Don't fail catastrophically, RDS might work with default if account allows

            # Use the same SG created for EC2, or create a new one allowing Postgres port 5432
            # For simplicity for now, we will assume the EC2_SG can be used (though RDS typically needs its own)
            rds_sg_id = state.get('ec2_sg_id') 
            if not rds_sg_id:
                print("Error: Security Group ID not found from EC2 setup, cannot create RDS instance.")
                return

            rds_client.create_db_instance(
                DBInstanceIdentifier=db_instance_identifier,
                AllocatedStorage=RDS_ALLOCATED_STORAGE,
                DBInstanceClass=RDS_INSTANCE_CLASS,
                Engine=RDS_ENGINE,
                EngineVersion=RDS_ENGINE_VERSION,
                MasterUsername=RDS_MASTER_USERNAME,
                MasterUserPassword=RDS_MASTER_PASSWORD,
                DBName=RDS_DB_NAME,
                VpcSecurityGroupIds=[rds_sg_id],
                DBSubnetGroupName=db_subnet_group_name,
                PubliclyAccessible=False, # Keep it private for testing
                Tags=RDS_TAGS,
                BackupRetentionPeriod=0, # Disable backups for test instance
                CopyTagsToSnapshot=False
            )
            print(f"RDS instance {db_instance_identifier} creation initiated. Waiting for it to become available...")
            waiter = rds_client.get_waiter('db_instance_available')
            waiter.wait(DBInstanceIdentifier=db_instance_identifier)
            print(f"RDS instance {db_instance_identifier} is available.")
            state['rds_instance_identifier'] = db_instance_identifier
            state['rds_region'] = region_name
            save_state(state)
        except ClientError as e:
            print(f"Error creating RDS instance: {e}")
        except WaiterError as e:
            print(f"Error waiting for RDS instance: {e}")
    else:
        print(f"RDS instance {state.get('rds_instance_identifier')} already exists in state.")
    
    print("--- Resource provisioning attempt complete. ---")

def spin_down_resources():
    """Spins down the test resources based on the state file."""
    state = load_state()
    if not state:
        print("No state file found. Nothing to tear down or resources not managed by this script.")
        return

    print("--- Starting resource teardown --- ")

    # --- 1. RDS Instance ---
    if state.get('rds_instance_identifier') and state.get('rds_region'):
        rds_client = boto3.client('rds', region_name=state['rds_region'])
        db_id = state['rds_instance_identifier']
        print(f"Deleting RDS instance: {db_id}...")
        try:
            rds_client.delete_db_instance(
                DBInstanceIdentifier=db_id,
                SkipFinalSnapshot=True, # Required for non-prod
                DeleteAutomatedBackups=True
            )
            waiter = rds_client.get_waiter('db_instance_deleted')
            print(f"Waiting for RDS instance {db_id} to be deleted...")
            waiter.wait(DBInstanceIdentifier=db_id)
            print(f"RDS instance {db_id} deleted.")
            state.pop('rds_instance_identifier', None)
            state.pop('rds_region', None)
            save_state(state)
            # Delete DB Subnet Group (best effort, might be in use if something went wrong)
            try:
                db_subnet_group_name = "guardpost-test-db-subnet-group"
                rds_client.delete_db_subnet_group(DBSubnetGroupName=db_subnet_group_name)
                print(f"DB Subnet Group '{db_subnet_group_name}' deleted.")
            except ClientError as e:
                if e.response['Error']['Code'] != 'DBSubnetGroupNotFoundFault':
                    print(f"Could not delete DB Subnet Group '{db_subnet_group_name}': {e}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'DBInstanceNotFoundFault':
                print(f"RDS instance {db_id} already deleted or not found.")
                state.pop('rds_instance_identifier', None)
                state.pop('rds_region', None)
                save_state(state)
            else:
                print(f"Error deleting RDS instance {db_id}: {e}")
        except WaiterError as e:
            print(f"Error waiting for RDS instance deletion: {e}")
    else:
        print("No RDS instance to delete in state.")

    # --- 2. EC2 Instance --- 
    if state.get('ec2_instance_id') and state.get('ec2_region'):
        ec2_client = boto3.client('ec2', region_name=state['ec2_region'])
        instance_id = state['ec2_instance_id']
        sg_id = state.get('ec2_sg_id')
        print(f"Terminating EC2 instance: {instance_id}...")
        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            waiter = ec2_client.get_waiter('instance_terminated')
            print(f"Waiting for EC2 instance {instance_id} to terminate...")
            waiter.wait(InstanceIds=[instance_id])
            print(f"EC2 instance {instance_id} terminated.")
            state.pop('ec2_instance_id', None)
            state.pop('ec2_region', None)
            
            # Delete Security Group (allow some time for instance to detach)
            if sg_id:
                print(f"Waiting a bit before deleting security group {sg_id}...")
                time.sleep(30) # Allow time for ENIs to detach etc.
                try:
                    ec2_client.delete_security_group(GroupId=sg_id)
                    print(f"Security group {sg_id} deleted.")
                    state.pop('ec2_sg_id', None)
                except ClientError as e:
                     print(f"Error deleting security group {sg_id}: {e} (Might need manual cleanup or is in use by another resource)")
            save_state(state)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                print(f"EC2 instance {instance_id} already terminated or not found.")
                state.pop('ec2_instance_id', None)
                state.pop('ec2_region', None)
                save_state(state)
            else:
                print(f"Error terminating EC2 instance {instance_id}: {e}")
        except WaiterError as e:
             print(f"Error waiting for EC2 termination: {e}")
    else:
        print("No EC2 instance to delete in state.")

    # --- 3. S3 Bucket --- 
    if state.get('s3_bucket_name') and state.get('s3_bucket_region'):
        bucket_name = state['s3_bucket_name']
        s3_client = boto3.client('s3', region_name=state['s3_bucket_region'])
        s3_resource = boto3.resource('s3', region_name=state['s3_bucket_region'])
        print(f"Emptying and deleting S3 bucket: {bucket_name}...")
        try:
            bucket = s3_resource.Bucket(bucket_name)
            bucket.objects.all().delete() # Empty the bucket
            print(f"Bucket {bucket_name} emptied.")
            # Some regions might have objects.delete() return None directly
            # Wait for objects to be deleted if necessary, though usually fast for few objects
            # For many objects, this can take time and might need a waiter or loop.

            s3_client.delete_bucket(Bucket=bucket_name)
            print(f"S3 bucket {bucket_name} deleted.")
            state.pop('s3_bucket_name', None)
            state.pop('s3_bucket_region', None)
            save_state(state)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                print(f"S3 bucket {bucket_name} already deleted or not found.")
                state.pop('s3_bucket_name', None)
                state.pop('s3_bucket_region', None)
                save_state(state)
            else:
                print(f"Error deleting S3 bucket {bucket_name}: {e}")
    else:
        print("No S3 bucket to delete in state.")
    
    # Clean up state file if empty
    if not state:
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)
            print(f"Cleaned up empty state file: {STATE_FILE}")

    print("--- Resource teardown attempt complete. --- ")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage AWS test resources for GuardPost blast radius testing.")
    parser.add_argument("action", choices=['up', 'down'], help="'up' to create resources, 'down' to delete them.")
    parser.add_argument("--region", default=DEFAULT_REGION, help=f"AWS region to operate in (default: {DEFAULT_REGION}).")
    parser.add_argument("--key-name", default=EC2_KEY_NAME, help=f"EC2 KeyPair name to use (must exist in the region, default: {EC2_KEY_NAME}).")
    
    args = parser.parse_args()

    EC2_KEY_NAME = args.key_name # Update global from arg

    if args.action == 'up':
        spin_up_resources(region_name=args.region)
    elif args.action == 'down':
        spin_down_resources() # Teardown doesn't need region as it reads from state file 