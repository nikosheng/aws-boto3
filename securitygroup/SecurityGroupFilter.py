# -*- coding: utf-8 -*-

"""Filter security group with following conditions:

1. for he source desc is Open-To-The-World(0.0.0.0/0)
2. for those ports which are not standard port(80/443) are open
3. for port range is 0-65535
4. for the security groups of database servers are Open-To-The-World(0.0.0.0/0)
5. for the public subnet with remote operation port (22/3389/111)

Input:
python SecurityGroupFilter.py [-r --region <Region>] [-u --update {\"bastion-cidr\":\"10.10.10.10/32\",\"invalid-src-dest\":\"no\",\"invalid-standard-port\":\"no\",\"invalid-port-range\":\"no\",\"invalid_db_sg\":\"yes\"}]


Output:
{
    "Stats": {
        "AccountId": "286792376082",
        "PubInstancesWithRemoteOps": {
            "Instances": [
                {
                    "InstanceId": "i-043a4d2ecb073cf4a",
                    "SecurityGroups": [
                        {
                            "GroupId": "sg-0cd6ae65",
                            "GroupName": "default"
                        }
                    ]
                }
            ]
        },
        "InvalidPortRange": [
            {
                "GroupId": "sg-0439d07ed8c4c09f7",
                "IpPermission": [
                    {
                        "Ipv6Ranges": [ ],
                        "IpRanges": [ ],
                        "UserIdGroupPairs": [
                            {
                                "GroupId": "sg-5f4c4f36",
                                "UserId": "286792376082"
                            }
                        ],
                        "PrefixListIds": [ ],
                        "IpProtocol": "-1"
                    }
                ]
            }
        ],
        "NonStandardPort": [
            {
                "GroupId": "sg-0439d07ed8c4c09f7",
                "IpPermission": [
                    {
                        "Ipv6Ranges": [ ],
                        "IpRanges": [ ],
                        "UserIdGroupPairs": [
                            {
                                "GroupId": "sg-5f4c4f36",
                                "UserId": "286792376082"
                            }
                        ],
                        "PrefixListIds": [ ],
                        "IpProtocol": "-1"
                    }
                ]
            }
        ],
        "SourceDescOpenToTheWorld": [
            {
                "GroupId": "sg-0cd6ae65",
                "IpPermission": [
                    {
                        "Ipv6Ranges": [ ],
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "UserIdGroupPairs": [ ],
                        "PrefixListIds": [ ],
                        "IpProtocol": "-1"
                    }
                ]
            }
        ],
        "DBSensitiveSecurityGroups": [
            {
                "GroupId": "sg-54d7af3d",
                "IpPermission": [
                    {
                        "PrefixListIds": [ ],
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "UserIdGroupPairs": [ ],
                        "ToPort": 22,
                        "Ipv6Ranges": [ ],
                        "FromPort": 22,
                        "IpProtocol": "tcp"
                    }
                ]
            }
        ]
    },
    "updateStats": [
        {
            "ResponseStatus": "Success",
            "ResponseMessage": "DBSensitiveSecurityGroups"
        }
    ]
}

"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import json
from datetime import date, datetime
import getopt
import sys
import logging
import time
import re

#################################################
#
# Global variables
#
#################################################
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a',
                    filename='SecurityGroupFilter.log.%d' % int(round(time.time() * 1000))
                    )

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


#################################################
#
# Validate the security groups which are open-to-the-world
#
#################################################
# def validate_sg_open_to_world(permissions):
#     for permission in permissions:
#         for ipRange in permission['IpRanges']:
#             if ipRange['CidrIp'] == '0.0.0.0/0':
#                 return True
#     return False

def validate_sg_open_to_world(ec2, securityGroups, **kwargs):
    # variables
    response = []

    for securityGroup in securityGroups:
        permissions = securityGroup['IpPermissions']
        for permission in permissions:
            for ipRange in permission['IpRanges']:
                if ipRange['CidrIp'] == '0.0.0.0/0':
                    group = {}
                    group['Before'] = {'SecurityGroup': securityGroup}
                    group['After'] = {}
                    if kwargs['opt'] == 'update':
                        res = update_invalid_rule_sg(ec2=ec2, groupId=securityGroup['GroupId'],
                                                     permission=permission, bastion=kwargs['bastion'])
                        group['After'] = {'SecurityGroup': res['ResponseBody']}
                    response.append(group)
    return response


#################################################
#
# # Validate the security groups which are exposing the non-standard ports
#
#################################################
# def validate_sg_non_standard_port(permissions):
#     for permission in permissions:
#         # All traffic has been set in security group
#         protocol = permission["IpProtocol"]
#         if "FromPort" not in permission:
#             port = None
#         else:
#             port = permission["FromPort"]
#
#         if (protocol, port) not in standard_protocol_port_pair:
#             return True
#     return False

def validate_sg_non_standard_port(ec2, securityGroups, **kwargs):
    # variables
    response = []

    for securityGroup in securityGroups:
        permissions = securityGroup['IpPermissions']
        for permission in permissions:
            # All traffic has been set in security group
            protocol = permission["IpProtocol"]
            if "FromPort" not in permission:
                port = None
            else:
                port = permission["FromPort"]

            if (protocol, port) not in standard_protocol_port_pair:
                group = {}
                group['Before'] = {'SecurityGroup': securityGroup}
                group['After'] = {}
                if kwargs['opt'] == 'update':
                    delete_invalid_rule_sg(ec2=ec2, groupId=securityGroup['GroupId'],
                                           permission=permission)
                response.append(group)
    return response

#################################################
#
# # Validate the security groups which are setting the 0-65535 port range
#
#################################################
def validate_sg_invalid_portrange(ec2, securityGroups, **kwargs):
    # variables
    response = []
    fromPort = None
    toPort = None

    for securityGroup in securityGroups:
        permissions = securityGroup['IpPermissions']
        for permission in permissions:
            if "FromPort" in permission:
                fromPort = permission["FromPort"]

            if "ToPort" in permission:
                toPort = permission["ToPort"]

            # the port range is consisted of multiple ports
            if abs(toPort - fromPort) > 0:
                group = {}
                group['Before'] = {'SecurityGroup': securityGroup}
                group['After'] = {}
                if kwargs['opt'] == 'update':
                    delete_invalid_rule_sg(ec2=ec2, groupId=securityGroup['GroupId'],
                                           permission=permission)
                response.append(group)
    return response


#################################################
#
# # Validate the db security groups which are open-to-the-world
#
#################################################
def validate_sg_db_invalid(ec2, rds, **kwargs):
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
                for securityGroup in sgDetails['SecurityGroups']:
                    permissions = securityGroup['IpPermissions']
                    for permission in permissions:
                        for ipRange in permission['IpRanges']:
                            if ipRange['CidrIp'] == '0.0.0.0/0':
                                group = {}
                                group['Before'] = {'SecurityGroup': securityGroup}
                                group['After'] = {}
                                if kwargs['opt'] == 'update':
                                    res = update_invalid_rule_sg(ec2=ec2, groupId=securityGroup['GroupId'],
                                                                 permission=permission, bastion=kwargs['bastion'])
                                    group['After'] = {'SecurityGroup': res['ResponseBody']}
                                response.append(group)
    return response


#################################################
#
# Validate the rds instance is public accessible or not
#
#################################################
def validate_db_public_accessible(rds):
    # variables
    response = []

    dbs = rds.describe_db_instances()
    for db in dbs['DBInstances']:
        if db['PubliclyAccessible']:
            return True
    return False


#################################################
#
# List the subnets which are attached with internet gateway
#
#################################################
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


#################################################
#
# List the ec2 instances which are in public subnet
#
#################################################
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


#################################################
#
# Validate the ec2 instances which contains the remote login operations
#
#################################################
def validate_public_subnet_remote_ops(ec2):
    # variables
    response = {}

    # list ec2 instances in the public subnet with security groups including remote login ports
    subnets = list_subnets_with_igw(ec2)
    instances = list_instances_in_public_subnets(ec2, subnets)
    response['Instances'] = instances
    return response


#################################################
#
# Helper message
#
#################################################
def help():
    print('''
    SecurityGroupFilter.py [-r --region <Region>] [-u --update {\"bastion-cidr\":\"10.10.10.10/32\",\"invalid-src-dest\":\"no\",\"invalid-standard-port\":\"no\",\"invalid-port-range\":\"no\",\"invalid_db_sg\":\"yes\"}]

    -r --region  Specify a region code to perform cloudtrail scan, if not specified, the program will set as the 
                 default region in environment setting
                 
    -u --update  Specify a json body including the update options for various conditions
    ''')


#################################################
#
# Delete security group rules which are invalid
#
#################################################
def delete_invalid_rule_sg(ec2, groupId, permission, msg=None):
    # variables
    response = {}

    try:
        ec2.revoke_security_group_ingress(
            GroupId=groupId,
            IpPermissions=[permission]
        )
        time.sleep(1)
        logging.debug("Security Group: [%s] has removed an invalid rule:  Rule: [%s]"
                      % (groupId, json.dumps(permission)))
    except Exception as err:
        response['ResponseStatus'] = 'Failed'
        response['ResponseMessage'] = err
        return response

    response['ResponseStatus'] = 'Success'
    response['ResponseMessage'] = msg
    logging.debug(response)
    return response


#################################################
#
# Add valid security group rules
#
#################################################
def add_rule_to_sg(ec2, groupId, permission, bastion=None, msg=None):
    # variables
    response = {}

    try:
        ec2.authorize_security_group_ingress(
            CidrIp=bastion,
            FromPort=permission['FromPort'],
            GroupId=groupId,
            IpProtocol=permission['IpProtocol'],
            ToPort=permission['ToPort']
        )
        time.sleep(1)

        sgroups = ec2.describe_security_groups(
            GroupIds=[
                groupId
            ]
        )

        logging.debug("Security Group: [%s] has added a new rule:  [CidrIp]: [%s] [FromPort]: [%s] [ToPort]: [%s]"
                      " [IpProtocol]: [%s]"
                      % (groupId, bastion, permission['FromPort'], permission['ToPort'],
                         permission['IpProtocol']))
    except Exception as err:
        response['ResponseStatus'] = 'Failed'
        response['ResponseMessage'] = err
        response['ResponseBody'] = None
        return response

    response['ResponseStatus'] = 'Success'
    response['ResponseMessage'] = msg
    response['ResponseBody'] = sgroups
    logging.debug(response)
    return response


#################################################
#
# Update invalid rule
#
#################################################
def update_invalid_rule_sg(ec2, groupId, permission, bastion=None, msg=None):
    delete_invalid_rule_sg(ec2=ec2, groupId=groupId, permission=permission, msg=msg)
    response = add_rule_to_sg(ec2=ec2, groupId=groupId, permission=permission, bastion=bastion, msg=msg)
    return response


#################################################
#
# Main Entry
#
#################################################
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hr:u:", ["help", "region=", "update="])
    except getopt.GetoptError:
        help()
        sys.exit(2)

    # init
    ec2 = boto3.client('ec2')
    rds = boto3.client('rds')
    sts = boto3.client('sts')

    # variables
    response = {}
    # filter result
    stats = {}
    # remove rules result
    updateStats = []
    # delete options
    conditions = {}

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
            sys.exit()
        if opt in ("-r", "--region"):
            ec2 = boto3.client('ec2', region_name=arg)
            rds = boto3.client('rds', region_name=arg)
            sts = boto3.client('sts', region_name=arg)
        if opt in ("-u", "--update"):
            conditions = json.loads(arg)

    # list all security groups
    security_groups = ec2.describe_security_groups()
    stats['AccountId'] = sts.get_caller_identity()['Account']

    if conditions:
        if conditions['invalid-src-dest'] == 'yes':
            stats['SourceDescOpenToTheWorld'] = validate_sg_open_to_world(ec2, security_groups['SecurityGroups'],
                                                                          opt='update',
                                                                          bastion=conditions['bastion-cidr'])

        if conditions['invalid-standard-port'] == 'yes':
            stats['NonStandardPort'] = validate_sg_non_standard_port(ec2, security_groups['SecurityGroups'],
                                                                     opt='update'
                                                                     )

        if conditions['invalid-port-range'] == 'yes':
            stats['InvalidPortRange'] = validate_sg_invalid_portrange(ec2, security_groups['SecurityGroups'],
                                                                      opt='update'
                                                                      )

        if conditions['invalid_db_sg'] == 'yes':
            stats['DBSensitiveSecurityGroups'] = validate_sg_db_invalid(ec2, rds,
                                                                        opt='update',
                                                                        bastion=conditions['bastion-cidr'])
    else:
        stats['SourceDescOpenToTheWorld'] = validate_sg_open_to_world(ec2, security_groups['SecurityGroups'])
        stats['NonStandardPort'] = validate_sg_non_standard_port(ec2, security_groups['SecurityGroups'])
        stats['InvalidPortRange'] = validate_sg_invalid_portrange(ec2, security_groups['SecurityGroups'])
        stats['DBSensitiveSecurityGroups'] = validate_sg_db_invalid(ec2, rds)
        stats['PubInstancesWithRemoteOps'] = validate_public_subnet_remote_ops(ec2)
    response['Stats'] = stats

    print(response)
    logging.info(response)


if __name__ == "__main__":
    main(sys.argv[1:])
