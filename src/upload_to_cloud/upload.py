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
COS_INSTANCE_CRN = COS_RESOURCE_CRN

cos_client = ibm_boto3.client("s3",
    ibm_api_key_id=COS_API_KEY_ID,
    ibm_service_instance_id=COS_INSTANCE_CRN,
    config=Config(signature_version="oauth"),
    endpoint_url=COS_ENDPOINT
)

def get_buckets():
    print("Retrieving list of buckets")
    try:
        buckets = cos_client.list_buckets()
        for bucket in buckets["Buckets"]:
            print("Bucket Name: {0}".format(bucket["Name"]))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve list buckets: {0}".format(e))


def get_bucket_contents(bucket_name):
    print("Retrieving bucket contents from: {0}".format(bucket_name))
    try:
        files = cos_client.list_objects(Bucket=bucket_name)
        for file in files.get("Contents", []):
            print("Item: {0} ({1} bytes).".format(file["Key"], file["Size"]))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve bucket contents: {0}".format(e))


def put_item(bucket_name, item_name, file_text):
    print("Ading to bucket: {0}, key: {1}".format(bucket_name, item_name))
    try:
        cos_client.put_object(
                Bucket=bucket_name,
                Key=item_name,
                Body=file_text)
        print("Item: {0} created!".format(item_name))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to create text file: {0}".format(e))

def upload_file(bucket_name, key, filename):
    print("Ading to bucket: {0}, key: {1}".format(bucket_name, key))
    try:
        with open(filename, 'rb') as data:
            cos_client.upload_fileobj(
                data,
                bucket_name,
                key)
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to create text file: {0}".format(e))

def main():
    global last_print_time_ns, csv_writer

    get_buckets()
    print("get bucket contents...")
    get_bucket_contents('bucket-ai-test')

    upload_file('bucket-ai-test', 'electricity.csv', '/home/sumit/code/electricity.csv') 

    return 0


if __name__ == "__main__":
    main()
