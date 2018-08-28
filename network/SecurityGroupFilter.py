# -*- coding: utf-8 -*-

"""Filter security group with following conditions:

1. for he source desc is Open-To-The-World(0.0.0.0/0)
2. for those ports which are not standard port(80/443) are open
3. for port range is 0-65535
4. for the security groups of database servers are Open-To-The-World(0.0.0.0/0)
5. for the public subnet with remote operation port (22/3389/111)

"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import json
from datetime import date, datetime

#################################################
#
# Global variables
#
#################################################
ec2 = boto3.client('ec2')
rds = boto3.client('rds')

# All Traffic / All TCP / All UDP / All ICMP
standard_protocol_port_pair = [("tcp", 80), ("tcp", 443)]

# Port Ranage
port_range = [(None, None), (0, 65535)]

# Remote Login Ports
remote_login_ports = [22, 3389, 111]

# Internet Gateway Available Status
igw_status = ['attaching', 'attached']

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


def validate_db_sg():
    pass


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


def validate_db_sg(permissions):
    dbsgs = rds.describe_db_security_groups()
    for dbsg in dbsgs['DBSecurityGroups']:
        for range in dbsg['IPRanges']:
            if range['CIDRIP'] == '0.0.0.0/0':
                return True
    return False


def list_subnets_with_igw():
    # variables
    gatewayIds = set()
    subnets = set()

    # list internet gateway
    response = ec2.describe_internet_gateways()
    for igw in response['InternetGateways']:
        attachments = igw['Attachments']
        for attachment in attachments:
            vpcId = attachment['VpcId']
            if attachment['State'] in igw_status:
                gatewayIds.add(igw['InternetGatewayId'])

    # list subnets with route tables including igw
    rtabels = ec2.describe_route_tables()
    for rtable in rtabels['RouteTables']:
        for route in rtable['Routes']:
            if route['GatewayId'] in gatewayIds:
                associations = rtable['Associations']
                for association in associations:
                    subnets.add(association['SubnetId'])
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


def list_instances_in_public_subnets(subnets):
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
    for instance in reservations['Instances']:
        sgs = instance['SecurityGroups']
        instance_body = {'InstanceId': instance['InstanceId'], 'SecurityGroups': instance['SecurityGroups']}
        instances.append(instance_body)
    return instances


def validate_public_subnet_remote_ops():
    # variables
    response = {}

    # list ec2 instances in the public subnet with security groups including remote login ports
    subnets = list_subnets_with_igw()
    instances = list_instances_in_public_subnets(subnets)
    response['Instances'] = instances
    return response


def main():
    # variables
    response = {}
    sensitive_sgs = set()

    # list all security groups
    security_groups = ec2.describe_security_groups()
    for sg in security_groups['SecurityGroups']:
        ipPermissions = sg['IpPermissions']
        if validate_sg_non_standard_port(permissions=ipPermissions) and \
                validate_sg_open_to_world(permissions=ipPermissions) and \
                validate_db_sg():
            sensitive_sgs.add(sg)
    response['SensitiveSecurityGroups'] = sensitive_sgs
    response['PubInstancesWithRemoteOps'] = validate_public_subnet_remote_ops()
    print(response)


if __name__ == "__main__":
    main()