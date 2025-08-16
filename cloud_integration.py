import boto3
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

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