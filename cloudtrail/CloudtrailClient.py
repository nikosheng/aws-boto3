# -*- coding: utf-8 -*-

"""Enable Cloudtrail and export to specific S3 bucket"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import sys
import getopt
import json


def help():
    print('''
    CloudtrailClient.py [-h --help] [-b <build> {'Region':<Region>, 'Name':<cloudtrail name>, 'S3BucketName':<S3BucketName>, 'S3KeyPrefix':<S3KeyPrefix>]

    -r --region  Specify a region code to perform cloudtrail scan, if not specified, the program will set as the 
                 default region in environment setting
    ''')


def main(argv):
    try:
        if len(argv):
            opts, args = getopt.getopt(argv, "hb:", ["build="])
        else:
            raise getopt.GetoptError('No argument found')
    except getopt.GetoptError:
        help()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            help()
            sys.exit()
        elif opt in ("-b", "--build"):
            arg_json = json.loads(json.dumps(arg))
            cloudtrail = boto3.client('cloudtrail', region_name=arg_json['Region'])
            # Verify cloudtrail is activated in account
            trails = cloudtrail.describe_trails()
            if not len(trails['trailList']):
                # if no, create cloudtrail and bind to a S3 bucket
                response = cloudtrail.create_trail(
                    Name=arg_json['Name'],
                    S3BucketName=arg_json['S3BucketName'],
                    S3KeyPrefix=arg_json['S3KeyPrefix']
                )
                print(response)
            else:
                print(trails)
            sys.exit()
        else:
            help()
            sys.exit()


if __name__ == "__main__":
    main(sys.argv[1:])
