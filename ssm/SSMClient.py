# -*- coding: utf-8 -*-

"""Attach SSM Role to EC2 Instance"""

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
SSMManagedPolicyArns = ['arn:aws-cn:iam::aws:policy/service-role/AmazonEC2RoleforSSM']
AssumeRolePolicyDocument = '{\"Version\": \"2012-10-17\",\"Statement\": {\"Effect\": \"Allow\",\"Principal\": {\"Service\": \"ec2.amazonaws.com.cn\"},\"Action\": \"sts:AssumeRole\"}}'


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
# Create SSM Role
#
#################################################
def createRole(iam, roleName, policyArns, desc=None):
    # Create a new Role
    roleResponse = iam.create_role(
        RoleName=roleName,
        AssumeRolePolicyDocument=AssumeRolePolicyDocument,
        Description=desc
    )
    role = roleResponse['Role']

    # Attach the SSM policies to the role
    for policyArn in policyArns:
        response = iam.attach_role_policy(
            RoleName=role['RoleName'],
            PolicyArn=policyArn
        )

    return role


#################################################
#
# Create Instance Profile
#
#################################################
def createInstanceProfile(iam, profileName, roleName):
    try:
        response = iam.create_instance_profile(
            InstanceProfileName=profileName
        )
        instanceProfile = response['InstanceProfile']

        iam.add_role_to_instance_profile(
            InstanceProfileName=instanceProfile['InstanceProfileName'],
            RoleName=roleName
        )
    except Exception as err:
        print(err)
        sys.exit(2)

    return instanceProfile


#################################################
#
# Get the role <SSMPermissionRoleForEC2>
#
#################################################
def getSSMPermissionRoleForEC2Existed(iam):
    # Check whether SSMPermissionRoleForEC2 and SSMPermissionRoleForEC2Profile are existed
    try:
        # Role
        roleRes = iam.get_role(
            RoleName='SSMPermissionRoleForEC2'
        )
        role = roleRes['Role']
        # Instance Profile
        profileRes = iam.get_instance_profile(
            InstanceProfileName='SSMPermissionRoleForEC2Profile'
        )
        instanceProfile = profileRes['InstanceProfile']
    except Exception as err:
        # Create a new SSM Role
        role = createRole(iam=iam, roleName='SSMPermissionRoleForEC2',
                          policyArns=SSMManagedPolicyArns,
                          desc='System Manager Permission Role for EC2')
        instanceProfile = createInstanceProfile(iam=iam,
                                                profileName='SSMPermissionRoleForEC2Profile',
                                                roleName=role['RoleName'])
    return role, instanceProfile

#################################################
#
# Get the role from instance profile
#
#################################################
def getRoleFromInstanceProfile(iam, instanceProfile):
    # variables
    roleNames = []

    instanceProfileArn = instanceProfile['Arn']
    instanceProfileName = instanceProfileArn[instanceProfileArn.rfind("/") + 1:]
    response = iam.get_instance_profile(
        InstanceProfileName=instanceProfileName
    )
    roles = response['InstanceProfile']['Roles']
    for role in roles:
        roleNames.append(role['RoleName'])

    return roleNames

#################################################
#
# Helper message
#
#################################################
def help():
    print('''
    SSMClient.py [--region <Region>]

    -r --region  Specify a region code to perform cloudtrail scan, if not specified, the program will set as the 
                 default region in environment setting
    ''')


#################################################
#
# Attach SSM Role Main Logic
#
#################################################
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hr:", ["help", "region="])
    except getopt.GetoptError:
        help()
        sys.exit(2)

    # init
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
            sys.exit()
        if opt in ("-r", "--region"):
            ec2 = boto3.client('ec2', region_name=arg)
            iam = boto3.client('iam', region_name=arg)

    # Check whether the SSMPermissionRoleForEC2 is existed
    role, instanceProfile = getSSMPermissionRoleForEC2Existed(iam=iam)

    # Scan each EC2 instance to search the attached role
    instance_response = ec2.describe_instances()
    instance_response_str = json.dumps(instance_response, cls=DateEncoder)
    instance_response_js = json.loads(instance_response_str)

    instances = []
    for reservation in instance_response_js['Reservations']:
        instances += reservation['Instances']

    for instance in instances:
        # If the instance is terminated, then skip the validation
        if instance['State']['Name'] == 'terminated':
            continue
        instance_id = instance['InstanceId']
        if 'IamInstanceProfile' in instance:
            # Matched Flag
            flag = False
            # If yes, then search the role of the policies to check whether the SSM policy is included
            instanceRoleNames = getRoleFromInstanceProfile(iam, instance['IamInstanceProfile'])
            # Get the attached managed policies
            attach_policies_entity = iam.list_attached_role_policies(
                RoleName=instanceRoleNames[0]
            )
            attach_policies = attach_policies_entity['AttachedPolicies']
            for policy in attach_policies:
                if policy['PolicyName'] == 'AmazonEC2RoleforSSM':
                    flag = True
                    print('Matched Instance: ' + instance_id)
            if not flag:
                print('UnMatched Instance: ' + instance_id)
                # Attach the <AmazonEC2RoleforSSM> policy to the EC2 instance
                res = iam.attach_role_policy(
                    RoleName=instanceRoleNames[0],
                    PolicyArn=SSMManagedPolicyArns[0]
                )
                print("Attached Successfully ==> Instance: " + instance_id)
        else:
            print('Without SSM Role ==> Instance: ' + instance_id)

            # Attach the role <SSMPermissionRoleForEC2> to the EC2 instance
            res = ec2.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': instanceProfile['Arn'],
                    'Name': instanceProfile['InstanceProfileName']
                },
                InstanceId=instance_id
            )
            print("Attached Successfully ==> Instance: " + instance_id)


if __name__ == "__main__":
    main(sys.argv[1:])
