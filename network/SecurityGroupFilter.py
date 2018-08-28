# -*- coding: utf-8 -*-

"""Filter security group with following conditions:

1. for he source desc is Open-To-The-World(0.0.0.0/0)
2. for those ports which are not standard port(80/443) are open
3. for port range is 0-65535
4. for the security groups of database servers are Open-To-The-World(0.0.0.0/0)
5. for the public subnet with remote operation port (22/3389/111)

Input:
python SecurityGroupFilter.py [--region <Region>]


Output:
{
    "SensitiveSecurityGroups": [
        "sg-0439d07ed8c4c09f7",
        "sg-0cd6ae65",
        "sg-0f621749f47a5a9a2",
        "sg-22c6be4b",
        "sg-403e1629",
        "sg-54d7af3d",
        "sg-5bb7b732",
        "sg-5c271f35",
        "sg-5f4c4f36",
        "sg-74ea911d",
        "sg-7ed48217",
        "sg-8ad6aee3",
        "sg-b3ceb6da",
        "sg-d36e4cba",
        "sg-f86f4d91"
    ],
    "DBSensitiveSecurityGroups": [
        "sg-54d7af3d"
    ],
    "PubInstancesWithRemoteOps": {
        "Instances": [
            {
                "InstanceId": "i-043a4d2ecb073cf4a",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-0cd6ae65"
                    }
                ]
            },
            {
                "InstanceId": "i-06cf5a4a7f9636b78",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-0cd6ae65"
                    }
                ]
            },
            {
                "InstanceId": "i-03ca9b57287d7fa78",
                "SecurityGroups": [
                    {
                        "GroupName": "allow-all-traffic",
                        "GroupId": "sg-5f4c4f36"
                    }
                ]
            },
            {
                "InstanceId": "i-089205aa25678afb0",
                "SecurityGroups": [
                    {
                        "GroupName": "allow-all-traffic",
                        "GroupId": "sg-5f4c4f36"
                    }
                ]
            },
            {
                "InstanceId": "i-07d96cbb3db15838c",
                "SecurityGroups": [
                    {
                        "GroupName": "default",
                        "GroupId": "sg-0cd6ae65"
                    }
                ]
            }
        ]
    }
}

"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import json
from datetime import date, datetime
import getopt
import sys

#################################################
#
# Global variables
#
#################################################


# All Traffic / All TCP / All UDP / All ICMP
standard_protocol_port_pair = [("tcp", 80), ("tcp", 443)]

# Port Ranage
port_range = [(None, None), (0, 65535)]

# Remote Login Ports
remote_login_ports = [22, 3389, 111]

# Internet Gateway Available Status
igw_status = ['available', 'attaching', 'attached']


#################################################
#
# Transform the Datetime format
#
#################################################
class DateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        else:
            return json.JSONEncoder.default(self, obj)


def validate_sg_open_to_world(permissions):
    for permission in permissions:
        for ipRange in permission['IpRanges']:
            if ipRange['CidrIp'] == '0.0.0.0/0':
                return True
    return False


def validate_sg_non_standard_port(permissions):
    for permission in permissions:
        # All traffic has been set in security group
        protocol = permission["IpProtocol"]
        if "FromPort" not in permission:
            port = None
        else:
            port = permission["FromPort"]

        if (protocol, port) not in standard_protocol_port_pair:
            return True
    return False


def validate_sg_portrange(permissions):
    # variables
    fromPort = None
    toPort = None

    for permission in permissions:
        if "FromPort" in permission:
            fromPort = permission["FromPort"]

        if "ToPort" in permission:
            toPort = permission["ToPort"]

        if (fromPort, toPort) in port_range:
            return True
    return False


def validate_db_sg(ec2, rds):
    # variables
    response = []

    dbs = rds.describe_db_instances()
    for db in dbs['DBInstances']:
        vpcSecurityGroups = db['VpcSecurityGroups']
        for vpcSecurityGroup in vpcSecurityGroups:
            groupId = vpcSecurityGroup['VpcSecurityGroupId']
            if vpcSecurityGroup['Status'] == 'active':
                sgDetails = ec2.describe_security_groups(
                    GroupIds=[
                        groupId
                    ]
                )
                for sgDetail in sgDetails['SecurityGroups']:
                    permissions = sgDetail['IpPermissions']
                    if validate_sg_open_to_world(permissions):
                        response.append(groupId)
    return response


def list_subnets_with_igw(ec2):
    # variables
    gatewayIds = []
    subnets = []

    # list internet gateway
    response = ec2.describe_internet_gateways()
    for igw in response['InternetGateways']:
        attachments = igw['Attachments']
        for attachment in attachments:
            vpcId = attachment['VpcId']
            if attachment['State'] in igw_status:
                gatewayIds.append(igw['InternetGatewayId'])

    # list subnets with route tables including igw
    rtabels = ec2.describe_route_tables()
    for rtable in rtabels['RouteTables']:
        for route in rtable['Routes']:
            if 'GatewayId' in route:
                if route['GatewayId'] in gatewayIds:
                    associations = rtable['Associations']
                    for association in associations:
                        if 'SubnetId' in association:
                            subnets.append(association['SubnetId'])
    return subnets


def validate_sg_remote_login(permissions):
    # variables
    fromPort = None
    toPort = None

    for permission in permissions:
        if "FromPort" in permission:
            fromPort = permission["FromPort"]

        if "ToPort" in permission:
            toPort = permission["ToPort"]

        if fromPort is None or toPort is None:
            return True

        for port in remote_login_ports:
            if port in range(fromPort, toPort):
                return True
    return False


def list_instances_in_public_subnets(ec2, subnets):
    # variables
    instances = []

    details = ec2.describe_instances(
        Filters=[
            {
                'Name': 'subnet-id',
                'Values': subnets
            }
        ]
    )
    reservations = details['Reservations']
    for reservation in reservations:
        for instance in reservation['Instances']:
            sgs = instance['SecurityGroups']
            instance_body = {'InstanceId': instance['InstanceId'], 'SecurityGroups': instance['SecurityGroups']}
            instances.append(instance_body)
    return instances


def validate_public_subnet_remote_ops(ec2):
    # variables
    response = {}

    # list ec2 instances in the public subnet with security groups including remote login ports
    subnets = list_subnets_with_igw(ec2)
    instances = list_instances_in_public_subnets(ec2, subnets)
    response['Instances'] = instances
    return response


def help():
    print('''
    SecurityGroupFilter.py [--region <Region>]

    -r --region  Specify a region code to perform cloudtrail scan, if not specified, the program will set as the 
                 default region in environment setting
    ''')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hr:", ["help", "region="])
    except getopt.GetoptError:
        help()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
            sys.exit()
        if opt in ("-r", "--region"):
            ec2 = boto3.client('ec2', region_name=arg)
            rds = boto3.client('rds', region_name=arg)
        else:
            ec2 = boto3.client('ec2')
            rds = boto3.client('rds')

    # variables
    response = {}
    sensitive_sgs = []

    # list all security groups
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        permissions = sg['IpPermissions']
        if validate_sg_non_standard_port(permissions) or \
                validate_sg_open_to_world(permissions):
            sensitive_sgs.append(sg['GroupId'])
    response['SensitiveSecurityGroups'] = sensitive_sgs
    response['DBSensitiveSecurityGroups'] = validate_db_sg(ec2=ec2, rds=rds)
    response['PubInstancesWithRemoteOps'] = validate_public_subnet_remote_ops(ec2)
    print(response)


if __name__ == "__main__":
    main(sys.argv[1:])
