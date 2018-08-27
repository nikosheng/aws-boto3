# -*- coding: utf-8 -*-

"""List the IAM users with network or IAM sensitive policies in each AWS services"""

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


#################################################
#
# Iterate the actions in the policies and search if any network or iam actions involved
#
#################################################
def get_user_policy(userName, policyName):
    res = iam.get_user_policy(
        UserName=userName,
        PolicyName=policyName
    )
    return res

def get_group_policy(groupName, policyName):
    res = iam.get_group_policy(
        GroupName=groupName,
        PolicyName=policyName
    )
    return res

def verifyUserPolicy(userName, policies):
    for policy in policies:
        policy_document = get_user_policy(userName, policy['PolicyName'])
        print(policy_document)

def verifyGroupPolicy(groupName, policies):
    for policy in policies:
        policy_document = get_group_policy(groupName, policy['PolicyName'])
        print(policy_document)


def main():
    # variables
    sensitive_users = []

    # list all the users
    users = json.loads(json.dumps(list_all_users(), cls=DateEncoder))

    # iterate the users to get the attached policies
    for user in users['Users']:
        sensitive_user = {}
        access_levels = []
        userName = user['UserName']
        # list the group policies that the user belongs to
        groups = iam.list_groups_for_user(
            UserName=userName
        )
        for group in groups['Groups']:
            groupName = group['GroupName']

            # list group's managed attache policies
            group_attached_policies = iam.list_attached_group_policies(
                GroupName=groupName
            )
            access_levels.append(verifyGroupPolicy(groupName, group_attached_policies['AttachedPolicies']))

            # list group's inline policies
            group_inline_policies = iam.list_group_policies(
                GroupName=groupName
            )
            access_levels.append(verifyGroupPolicy(userName, group_inline_policies['PolicyNames']))

        # list the user's attached policy
        user_attached_policies = iam.list_attached_user_policies(
            UserName=userName
        )
        verifyUserPolicy(userName, user_attached_policies['AttachedPolicies'])

        # list the user's inline policy
        user_inline_policies = iam.list_user_policies(
            UserName=userName
        )
        # user_inline_policies['PolicyNames']

        # verify the policies



if __name__ == "__main__":
    main()