# config.py
# This file handles AWS authentication and service clients

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def get_session(profile_name=None, region="us-east-1"):
    """
    Create AWS session.
    This will automatically use:
    - AWS CLI credentials
    - IAM role
    - Environment variables
    """
    try:
        # Try to create session with given profile
        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region)
        else:
            session = boto3.Session(region_name=region)
        
        # Quick test to see if credentials work
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        print(f"✅ Connected to AWS as: {identity['Arn']}")
        return session
        
    except NoCredentialsError:
        print("❌ ERROR: No AWS credentials found!")
        print("Run: aws configure OR set AWS_ACCESS_KEY_ID environment variables")
        exit(1)
    except ClientError as e:
        print(f"❌ ERROR: Cannot connect to AWS: {e}")
        exit(1)

def get_clients(session):
    """
    Create clients for all AWS services we need to check
    """
    clients = {
        "iam": session.client("iam"),
        "s3": session.client("s3"),
        "ec2": session.client("ec2"),
        "cloudtrail": session.client("cloudtrail"),
    }
    print("✅ Created clients for AWS services")
    return clients