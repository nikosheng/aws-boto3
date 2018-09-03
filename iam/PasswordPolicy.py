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
python PasswordPolicy.py [-h --help] [-o --operation {\"update-policy\":\"yes\",\"reset-passwd\":\"yes\"}]


"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import getopt
import sys
import json
import logging
import time


#################################################
#
# Global variables
#
#################################################
iam = boto3.client('iam')
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt='%Y-%m-%d  %H:%M:%S %a',
                    filename='PasswordPolicy.log.%d' % int(round(time.time() * 1000))
                    )

#################################################
#
# Helper message
#
#################################################
def help():
    print('''
    PasswordPolicy.py [-h --help] [-o --operation {\"update-policy\":\"yes\",\"reset-passwd\":\"yes\"}]

    -h --help       Get help message
    -o --operation  Specify the operations
                    1. update the password policy (value=yes)
                    2. reset the password for all IAM users (value=yes)
    ''')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "ho:", ["help", "operation="])
    except getopt.GetoptError:
        help()
        sys.exit(2)

    # init
    iam = boto3.client('iam')

    # variables
    operations = {}

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
            sys.exit()
        if opt in ("-o", "--operation"):
            operations = json.loads(arg)

    if operations:
        if operations['update-policy'] == 'yes':
            response = iam.update_account_password_policy(
                MinimumPasswordLength=8,
                RequireSymbols=True,
                RequireNumbers=True,
                RequireUppercaseCharacters=True,
                RequireLowercaseCharacters=True,
                PasswordReusePrevention=3,
                HardExpiry=True
            )
            logging.info(response)
            sys.exit()
        elif operations['reset-passwd'] == 'yes':
            # list all the users
            usersResponse = iam.list_users()
            users = usersResponse['Users']

            for user in users:
                loginProfile = iam.update_login_profile(
                    UserName=user['UserName'],
                    PasswordResetRequired=True
                )
                logging.info("User[" + user['UserName'] + "] has been requested to reset password")
            sys.exit()


if __name__ == "__main__":
    main(sys.argv[1:])