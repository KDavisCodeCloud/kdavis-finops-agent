"""AWS cross-account onboarding: external ID generation, the exact
trust/permissions policy JSON a customer needs to paste into AWS, and
assume-role verification/session building.

The permissions policy is scoped to exactly the API calls
kdavis-cloud-audit's AWSProvider.collect() makes -- not the broad
AWS-managed ReadOnlyAccess policy. If a new check is added to that
provider, this policy needs a matching action added here.
"""

import os
import secrets

import boto3
from botocore.exceptions import ClientError

# A boto3.Session built from raw assumed-role credentials (no ~/.aws/config
# behind it) has no region at all -- confirmed live 2026-09-11: EC2/RDS/S3/
# Security Hub all failed with "You must specify a region." Cost Explorer,
# IAM, and STS are global/us-east-1-only APIs so they never surfaced this.
_DEFAULT_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

_PERMISSIONS_POLICY_ACTIONS = [
    "ce:GetCostAndUsage",
    "ec2:DescribeInstances",
    "ec2:DescribeVolumes",
    "cloudwatch:GetMetricStatistics",
    "rds:DescribeDBInstances",
    "s3:ListAllMyBuckets",
    "s3:GetLifecycleConfiguration",
    "s3:GetBucketVersioning",
    "s3:GetBucketLocation",
    "securityhub:GetFindings",
    "iam:GetAccountSummary",
    "iam:ListUsers",
    "iam:ListMFADevices",
    "iam:ListAccessKeys",
    "support:DescribeTrustedAdvisorChecks",
    "support:DescribeTrustedAdvisorCheckResult",
]


def generate_external_id() -> str:
    return secrets.token_urlsafe(24)


def build_trust_policy(finops_account_id: str, external_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{finops_account_id}:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }
        ],
    }


def build_permissions_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": _PERMISSIONS_POLICY_ACTIONS,
                "Resource": "*",
            }
        ],
    }


class AssumeRoleError(Exception):
    """Raised when the customer's role can't be assumed -- wraps the AWS error message."""


def _assume_role(role_arn: str, external_id: str, session_name: str) -> dict:
    sts = boto3.client("sts")
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            ExternalId=external_id,
            RoleSessionName=session_name,
        )
    except ClientError as exc:
        raise AssumeRoleError(str(exc)) from exc
    return response["Credentials"]


def verify_role(role_arn: str, external_id: str) -> None:
    """Raises AssumeRoleError if the role can't be assumed. Doesn't return the creds --
    verification only, the scan endpoint assumes fresh each time."""
    _assume_role(role_arn, external_id, session_name="finops-verify")


def assume_role_session(role_arn: str, external_id: str) -> boto3.Session:
    """Assumes the role fresh and returns a boto3.Session built from the temp
    credentials. Never cache these -- they expire (default 1 hour)."""
    creds = _assume_role(role_arn, external_id, session_name="finops-scan")
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=_DEFAULT_REGION,
    )
