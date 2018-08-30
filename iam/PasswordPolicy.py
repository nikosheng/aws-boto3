"""
Setup the Password Policy with following conditions:
1. The minimum number of characters is 8
2. Specifies whether IAM user passwords must contain at least one of the following non-alphanumeric characters:
! @ # $ % ^ * ( ) _ + - = [ ] { } | '
3. Specifies whether IAM user passwords must contain at least one numeric character (0 to 9).
4. Specifies whether IAM user passwords must contain at least one uppercase character from the ISO basic Latin alphabet (A to Z).
5. Specifies whether IAM user passwords must contain at least one lowercase character from the ISO basic Latin alphabet (a to z).
6. The password never expires
7. Specifies the number of previous passwords(3) that IAM users are prevented from reusing
8. Prevents IAM users from setting a new password after their password has expired. The IAM user cannot be accessed until an administrator resets the password.

Input:
python PasswordPolicy.py

"""

__author__ = 'jiasfeng@amazon.com'

import boto3


#################################################
#
# Global variables
#
#################################################
iam = boto3.client('iam')


def main():
    response = iam.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        MaxPasswordAge=0,
        PasswordReusePrevention=3,
        HardExpiry=True
    )
    print(response)


if __name__ == "__main__":
    main()