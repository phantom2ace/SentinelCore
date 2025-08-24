import os
import logging
import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from google.cloud import compute_v1
import oci
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('SentinelCloud')

def discover_aws_resources():
    """Discover AWS EC2 instances"""
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_instances()
        
        resources = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                resources.append({
                    'id': instance['InstanceId'],
                    'type': 'EC2',
                    'state': instance['State']['Name'],
                    'ip': instance.get('PublicIpAddress', instance['PrivateIpAddress']),
                    'os': instance.get('Platform', 'Linux/UNIX')
                })
        return resources
    except Exception as e:
        logger.error(f"AWS discovery failed: {str(e)}")
        return []

def discover_azure_resources(subscription_id):
    """Discover Azure virtual machines"""
    try:
        credential = DefaultAzureCredential()
        resource_client = ResourceManagementClient(credential, subscription_id)
        
        resources = []
        for resource in resource_client.resources.list(filter="resourceType eq 'Microsoft.Compute/virtualMachines'"):
            resources.append({
                'id': resource.id,
                'name': resource.name,
                'type': resource.type,
                'location': resource.location
            })
        return resources
    except Exception as e:
        logger.error(f"Azure discovery failed: {str(e)}")
        return []

def discover_gcp_resources():
    """Discover Google Cloud Platform virtual machines"""
    try:
        # Get GCP project ID from environment variable
        project_id = os.getenv('GCP_PROJECT_ID')
        if not project_id:
            logger.error("GCP_PROJECT_ID environment variable not set")
            return []
            
        # Initialize the GCP compute client
        instance_client = compute_v1.InstancesClient()
        
        # List all zones
        request = compute_v1.ListZonesRequest()
        request.project = project_id
        zones_client = compute_v1.ZonesClient()
        zones = zones_client.list(request=request)
        
        resources = []
        # List instances in each zone
        for zone in zones:
            request = compute_v1.ListInstancesRequest()
            request.project = project_id
            request.zone = zone.name
            instances = instance_client.list(request=request)
            
            for instance in instances:
                # Get the public IP if available, otherwise use private IP
                ip_address = None
                for interface in instance.network_interfaces:
                    if interface.access_configs and len(interface.access_configs) > 0:
                        ip_address = interface.access_configs[0].nat_i_p
                        break
                if not ip_address and instance.network_interfaces:
                    ip_address = instance.network_interfaces[0].network_i_p
                
                resources.append({
                    'id': instance.id,
                    'name': instance.name,
                    'type': 'VM',
                    'location': zone.name,
                    'ip': ip_address,
                    'status': instance.status,
                    'machine_type': instance.machine_type.split('/')[-1],
                    'cloud_provider': 'GCP'
                })
                
        logger.info(f"Discovered {len(resources)} GCP instances")
        return resources
    except Exception as e:
        logger.error(f"GCP discovery failed: {str(e)}")
        return []

def discover_oci_resources():
    """Discover Oracle Cloud Infrastructure compute instances"""
    try:
        # Get OCI config file path and profile from environment variables
        config_file = os.getenv('OCI_CONFIG_FILE')
        profile = os.getenv('OCI_PROFILE', 'DEFAULT')
        
        if not config_file:
            logger.error("OCI_CONFIG_FILE environment variable not set")
            return []
            
        # Initialize OCI client
        config = oci.config.from_file(file_location=config_file, profile_name=profile)
        compute_client = oci.core.ComputeClient(config)
        network_client = oci.core.VirtualNetworkClient(config)
        identity_client = oci.identity.IdentityClient(config)
        
        # Get compartments
        compartments = []
        try:
            compartments_response = identity_client.list_compartments(
                compartment_id=config['tenancy'],
                compartment_id_in_subtree=True
            )
            compartments = [comp.id for comp in compartments_response.data]
            # Add the root compartment (tenancy)
            compartments.append(config['tenancy'])
        except Exception as e:
            logger.error(f"Failed to list OCI compartments: {str(e)}")
            compartments = [config['tenancy']]  # Fallback to just the tenancy
        
        resources = []
        # List instances in each compartment
        for compartment_id in compartments:
            try:
                instances = compute_client.list_instances(compartment_id=compartment_id).data
                
                for instance in instances:
                    # Get the VNIC attachments for this instance
                    vnic_attachments = compute_client.list_vnic_attachments(
                        compartment_id=compartment_id,
                        instance_id=instance.id
                    ).data
                    
                    ip_address = None
                    for vnic_attachment in vnic_attachments:
                        if vnic_attachment.lifecycle_state == "ATTACHED":
                            vnic = network_client.get_vnic(vnic_attachment.vnic_id).data
                            ip_address = vnic.public_ip or vnic.private_ip
                            break
                    
                    resources.append({
                        'id': instance.id,
                        'name': instance.display_name,
                        'type': 'VM',
                        'location': instance.availability_domain,
                        'ip': ip_address,
                        'status': instance.lifecycle_state,
                        'shape': instance.shape,
                        'cloud_provider': 'OCI'
                    })
            except Exception as e:
                logger.error(f"Failed to list OCI instances in compartment {compartment_id}: {str(e)}")
                continue
                
        logger.info(f"Discovered {len(resources)} OCI instances")
        return resources
    except Exception as e:
        logger.error(f"OCI discovery failed: {str(e)}")
        return []