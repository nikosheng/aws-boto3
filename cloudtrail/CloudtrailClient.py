# -*- coding: utf-8 -*-

"""Enable Cloudtrail and export to specific S3 bucket"""

__author__ = 'jiasfeng@amazon.com'

import boto3
import sys
import getopt
import json


def help():
    print('''
    CloudtrailClient.py [-h --help] [-b <build> "{\"Region\":\"<Region>\", \"Name\":\"<cloudtrail name>\", \"S3BucketName\":\"<S3BucketName>\", \"S3KeyPrefix\":\"<S3KeyPrefix>\"]

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
            arg_json = json.loads(arg)
            cloudtrail = boto3.client('cloudtrail', region_name=arg_json['Region'])
            # Verify cloudtrail is activated in account
            trails = cloudtrail.describe_trails()
            if not len(trails['trailList']):
                # if no, create cloudtrail and bind to a S3 bucket
                try:
                    trailDetail = cloudtrail.create_trail(
                        Name=arg_json['Name'],
                        S3BucketName=arg_json['S3BucketName'],
                        S3KeyPrefix=arg_json['S3KeyPrefix'],
                        IsMultiRegionTrail=True
                    )
                    response = {'Name': trailDetail['Name'],
                                'S3BcketName': trailDetail['S3BucketName'],
                                'S3KeyPrefix': trailDetail['S3KeyPrefix'],
                                'TrailARN': trailDetail['TrailARN']}
                    print(response)
                    # Enable the logging
                    cloudtrail.start_logging(
                        Name=arg_json['Name']
                    )
                except Exception as err:
                    print(err)
            else:
                print(trails)
        else:
            help()
            sys.exit()


if __name__ == "__main__":
    main(sys.argv[1:])
