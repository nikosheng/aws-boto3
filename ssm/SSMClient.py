# -*- coding: utf-8 -*-

"""Attach SSM Role to EC2 Instance"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import json
from datetime import date, datetime

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
# Attach SSM Role Main Logic
#
#################################################
def main():
    ssm = boto3.client('ssm')
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')

    # Scan each EC2 instance to search the attached role
    instance_response = ec2.describe_instances()
    instance_response_str = json.dumps(instance_response, cls=DateEncoder)
    instance_response_js = json.loads(instance_response_str)

    instance_group = instance_response_js['Reservations']
    for instance in instance_group:
        # If the instance is terminated, then skip the validation
        if instance['Instances'][0]['State']['Name'] == 'terminated':
            continue
        instance_id = instance['Instances'][0]['InstanceId']
        if 'IamInstanceProfile' in instance['Instances'][0]:
            # Matched Flag
            flag = False
            # If yes, then search the role of the policies to check whether the SSM policy is included
            # sample: arn:aws-cn:iam::<Account>:instance-profile/ecsInstanceRole
            instance_role_arn = instance['Instances'][0]['IamInstanceProfile']['Arn']
            instance_role = instance_role_arn[instance_role_arn.rfind('/') + 1:]
            # Get the attached managed policies
            attach_policies_entity = iam.list_attached_role_policies(
                RoleName=instance_role
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
                    RoleName=instance_role,
                    PolicyArn='arn:aws-cn:iam::aws:policy/service-role/AmazonEC2RoleforSSM'
                )
                print("Attached Successfully ==> Instance: " + instance_id)
        else:
            print('Without SSM Role ==> Instance: ' + instance_id)
            # Attach the <AmazonEC2RoleforSSM> policy to the EC2 instance
            res = ec2.associate_iam_instance_profile(
                IamInstanceProfile={
                    'Arn': 'arn:aws-cn:iam::286792376082:instance-profile/SSMFullPermissionRole',
                    'Name': 'SSMFullPermissionRole'
                },
                InstanceId=instance['Instances'][0]['InstanceId']
            )
            print("Attached Successfully ==> Instance: " + instance_id)


if __name__ == "__main__":
    main()
