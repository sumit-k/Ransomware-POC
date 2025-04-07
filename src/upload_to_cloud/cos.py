#!/usr/bin/env python3

import argparse
import ctypes as ct
import math
import os
import sys
import time
import csv
from collections import Counter, deque, namedtuple
from statistics import mean, variance
from datetime import datetime
from dotenv import load_dotenv

import ibm_boto3
from ibm_botocore.client import Config, ClientError

# Constants for IBM COS values
COS_ENDPOINT = ""
COS_API_KEY_ID = ""
COS_AUTH_ENDPOINT = ""
COS_RESOURCE_CRN = ""

# Create resource
cos = ibm_boto3.resource("s3",
    ibm_api_key_id=COS_API_KEY_ID,
    ibm_service_instance_id=COS_RESOURCE_CRN,
    ibm_auth_endpoint=COS_AUTH_ENDPOINT,
    config=Config(signature_version="oauth"),
    endpoint_url=COS_ENDPOINT
)

def get_buckets():
    print("Retrieving list of buckets")
    try:
        buckets = cos.buckets.all()
        for bucket in buckets:
            print("Bucket Name: {0}".format(bucket.name))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve list buckets: {0}".format(e))

def get_bucket_contents(bucket_name):
    print("Retrieving bucket contents from: {0}".format(bucket_name))
    try:
        files = cos.Bucket(bucket_name).objects.all()
        for file in files:
            print("Item: {0} ({1} bytes).".format(file.key, file.size))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve bucket contents: {0}".format(e))

# get_bucket_contents('gamification-cos-standard-tkq')

def get_item(bucket_name, item_name):
    print("Retrieving item from bucket: {0}, key: {1}".format(bucket_name, item_name))
    try:
        file = cos.Object(bucket_name, item_name).get()
        print("File Contents: {0}".format(file["Body"].read()))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve file contents: {0}".format(e))

#get_item('gamification-cos-standard-data', '50017.jpg')

def put_item(bucket_name, item_name):
    print("Ading to bucket: {0}, key: {1}".format(bucket_name, item_name))
    try:
        cos.Object(bucket_name, item_name).put()
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to upload file contents: {0}".format(e))



# --- Main Execution (Modified for Upload Option) ---
def main():
    global last_print_time_ns, csv_writer

    get_buckets()
    print("get bucket contents...")
    get_bucket_contents('bucket-ai-test')

    put_item('bucket-ai-test', '/home/sumit/code/expr/10.csv') 

    return 0


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("Error: This script requires root privileges (sudo) to run eBPF programs.", file=sys.stderr)
        sys.exit(1)

    # Add a warning if keys are passed via command line
    main()
