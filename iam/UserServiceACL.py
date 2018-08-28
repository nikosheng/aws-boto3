# -*- coding: utf-8 -*-

"""List the IAM users with ec2, network or IAM sensitive policies in each AWS services"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import json
from datetime import date, datetime

#################################################
#
# Global variables
#
#################################################
iam = boto3.client('iam')
restricted_managed_policies = ['AdministratorAccess',
                               'AmazonVPCFullAccess',
                               'IAMFullAccess',
                               'AmazonEC2FullAccess']

restricted_actions = ['*',
                      "ec2:*",
                      "ec2:*Vpc*",
                      "ec2:*Subnet*",
                      "ec2:*Gateway*",
                      "ec2:*Vpn*",
                      "ec2:*Route*",
                      "ec2:*Address*",
                      "ec2:*SecurityGroup*",
                      "ec2:*NetworkAcl*",
                      "iam:*",
                      "iam:*Create*",
                      "iam:*Delete*",
                      "iam:*Put*",
                      "iam:*Attach*",
                      "iam:*Detach*",
                      "iam:*Update*"]


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
# List all the users
#
#################################################
def list_all_users():
    return iam.list_users()


#################################################
#
# List all the users with path prefix
#
#################################################
def list_all_users_with_prefix(prefix):
    users = iam.list_users(
        PathPrefix=prefix
    )
    return users


def verify_inline_policy(policyDocument):
    statements = policyDocument['Statement']
    for statement in statements:
        action = statement['Action']
        effect = statement['Effect']
        if action in restricted_actions and effect == 'Allow':
            return True
    return False


def main():
    # variables
    sensitive_users = set()

    # list all the users
    users = json.loads(json.dumps(list_all_users(), cls=DateEncoder))

    # iterate the users to get the attached policies
    for user in users['Users']:
        userName = user['UserName']

        #################################################
        #
        # Managed User & Inline User Policies
        #
        #################################################
        # list the user's inline policy
        user_inline_policies = iam.list_user_policies(
            UserName=userName
        )
        # get the details of the inline policies
        for policyName in user_inline_policies['PolicyNames']:
            user_policy = iam.get_user_policy(
                UserName=userName,
                PolicyName=policyName
            )
            if verify_inline_policy(user_policy['PolicyDocument']):
                sensitive_users.add(userName)

        # list the user's attached policy
        user_attached_policies = iam.list_attached_user_policies(
            UserName=userName
        )
        for attached_policy in user_attached_policies['AttachedPolicies']:
            # verify the policy is in restricted managed policies
            if attached_policy['PolicyName'] in restricted_managed_policies:
                sensitive_users.add(userName)

        #################################################
        #
        # Managed Group & Inline Group Policies
        #
        #################################################
        groups = iam.list_groups_for_user(
            UserName=userName
        )
        for group in groups['Groups']:
            groupName = group['GroupName']
            # list the group's inline policy
            group_inline_policies = iam.list_group_policies(
                GroupName=groupName
            )
            # get the details of the inline policies
            for policyName in group_inline_policies['PolicyNames']:
                user_policy = iam.get_user_policy(
                    GroupName=groupName,
                    PolicyName=policyName
                )
                if verify_inline_policy(user_policy['PolicyDocument']):
                    sensitive_users.add(userName)
            # list the group's attached policy
            group_attached_policies = iam.list_attached_group_policies(
                GroupName=groupName
            )
            for attached_policy in group_attached_policies['AttachedPolicies']:
                # verify the policy is in restricted managed policies
                if attached_policy['PolicyName'] in restricted_managed_policies:
                    sensitive_users.add(userName)
    print(sensitive_users)


if __name__ == "__main__":
    main()
