import boto3
from botocore.client import ClientError
import json

# Initialize IAM, S3, and STS clients
iam_client = boto3.client('iam')
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')

# Get the AWS's Account ID
def get_account_id():
    return sts_client.get_caller_identity()['Account']


# Step 1: Create IAM Roles and Attach Policies
def create_iam_roles(role_name, policy_arn, trust_user_arn=None):
    # check whether the role already exists
    try:
        role = iam_client.get_role(RoleName=role_name)
        print(f"Role {role_name} already exists.")
        return role['Role']['Arn']
    except ClientError as e:
        # the role does not exist, then create
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"Creating {role_name} now...")
            if trust_user_arn:
                assume_role_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": trust_user_arn},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            else:
                assume_role_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }

            role = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_policy)
            )

            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            return role['Role']['Arn']
        else:
            raise e


def attach_policy_to_roles():
    account_id = get_account_id()
    user_arn = f"arn:aws:iam::{account_id}:user/test-user"

    # Attach full S3 access to Dev role
    create_iam_roles('Dev', 'arn:aws:iam::aws:policy/AmazonS3FullAccess', trust_user_arn=user_arn)

    # Attach read-only S3 access to User role
    read_only_access_s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::lecture1",
                    f"arn:aws:s3:::lecture1/*",
                ],
            }
        ],
    }

    read_only_policy_response = iam_client.create_policy(
        PolicyName="ReadOnlyS3Access",
        PolicyDocument=json.dumps(read_only_access_s3_policy)
    )

    read_only_access_s3_policy_arn = read_only_policy_response["Policy"]["Arn"]
    create_iam_roles('User', read_only_access_s3_policy_arn, trust_user_arn=user_arn)


# Step 2: Create IAM User
def create_iam_user(username):
    # check whether the user already exists
    try:
        user = iam_client.get_user(UserName=username)
        print(f"IAM User {username} already exists.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            user = iam_client.create_user(UserName=username)
            print(f'IAM User {username} created successfully')

    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }
        ]
    }

    try:
        iam_client.put_user_policy(
            UserName=username,
            PolicyName='AssumeUserRolePolicy',
            PolicyDocument=json.dumps(assume_role_policy)
        )
        print(f'Policy AssumeUserRolePolicy attached to user {username}')
    except ClientError as e:
        print(f'Failed to attach policy: {e}')
        raise e


# Step 3: Assume Dev Role and Create S3 Bucket & Objects
def assume_dev_role_and_create_s3_resources():
    account_id = get_account_id()
    dev_role_arn = f"arn:aws:iam::{account_id}:role/Dev"

    assumed_role = sts_client.assume_role(
        RoleArn=dev_role_arn,
        RoleSessionName="AssumeDevRoleSession"
    )

    credentials = assumed_role['Credentials']
    dev_s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-west-2'
    )

    bucket_name = 'lecture1'

    # check whether the bucket already exists
    try:
        dev_s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': 'us-west-2'})
        print(f'S3 bucket {bucket_name} created successfully')
    except ClientError as e:
        if e.response['Error']['Code'] in ['BucketAlreadyExists', 'BucketAlreadyOwnedByYou']:
            print(f"S3 bucket {bucket_name} already exists.")
        else:
            raise e

    # Upload files to buckets
    s3_client.put_object(Bucket=bucket_name, Key='assignment1.txt', Body='Empty Assignment 1')
    print('assignment1.txt uploaded')
    s3_client.put_object(Bucket=bucket_name, Key='assignment2.txt', Body='Empty Assignment 2')
    print('assignment2.txt uploaded')
    with open('recording1.jpg', 'rb') as img_file:
        dev_s3_client.put_object(Bucket=bucket_name, Key='recording1.jpg', Body=img_file)

    print('recording1.jpg uploaded')

# Step 4: Assume User Role and Calculate Objects Size
def assume_user_role_and_calculate_objects_size():
    account_id = get_account_id()
    user_role_arn = f"arn:aws:iam::{account_id}:role/User"

    assumed_role = sts_client.assume_role(
        RoleArn=user_role_arn,
        RoleSessionName="AssumeUserRoleSession"
    )

    credentials = assumed_role['Credentials']
    user_s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-west-2'
    )

    bucket_name = 'lecture1'
    objects = user_s3_client.list_objects_v2(Bucket=bucket_name, Prefix='assignment')

    total_size = sum(obj['Size'] for obj in objects.get('Contents', []))
    print(f"Total size of 'assignment' objects: {total_size} bytes")


# Step 5: Delete Objects and Bucket
def assume_dev_role_and_delete_objects():
    account_id = get_account_id()
    dev_role_arn = f"arn:aws:iam::{account_id}:role/Dev"

    assumed_role = sts_client.assume_role(
        RoleArn=dev_role_arn,
        RoleSessionName="AssumeDevRoleSession"
    )

    credentials = assumed_role['Credentials']
    dev_s3_client = boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name='us-west-2'
    )

    bucket_name = 'lecture1'
    try:
        objects = dev_s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in objects:
            for obj in objects['Contents']:
                dev_s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
                print(f"Object {obj['Key']} deleted successfully")

        dev_s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Bucket {bucket_name} deleted successfully")
    except ClientError as e:
        print(f"Failed to delete objects or bucket: {e}")
        raise e


# Main execution function
if __name__ == '__main__':
    attach_policy_to_roles()
    create_iam_user('test-user')
    assume_dev_role_and_create_s3_resources()
    assume_user_role_and_calculate_objects_size()
    assume_dev_role_and_delete_objects()
