from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from core.aws_onboarding import (
    AssumeRoleError,
    assume_role_session,
    build_permissions_policy,
    build_trust_policy,
    generate_external_id,
    verify_role,
)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "AssumeRole")


class TestGenerateExternalId:
    def test_generates_a_non_trivial_random_value(self):
        a = generate_external_id()
        b = generate_external_id()
        assert a != b
        assert len(a) > 16


class TestBuildTrustPolicy:
    def test_scopes_to_our_account_and_the_external_id(self):
        policy = build_trust_policy("111111111111", "ext-abc")
        statement = policy["Statement"][0]
        assert statement["Principal"]["AWS"] == "arn:aws:iam::111111111111:root"
        assert statement["Condition"]["StringEquals"]["sts:ExternalId"] == "ext-abc"
        assert statement["Action"] == "sts:AssumeRole"


class TestBuildPermissionsPolicy:
    def test_covers_every_aws_provider_read_call(self):
        policy = build_permissions_policy()
        actions = policy["Statement"][0]["Action"]
        for required in (
            "ce:GetCostAndUsage",
            "ec2:DescribeInstances",
            "rds:DescribeDBInstances",
            "s3:ListAllMyBuckets",
            "securityhub:GetFindings",
            "iam:GetAccountSummary",
            "support:DescribeTrustedAdvisorChecks",
        ):
            assert required in actions


class TestVerifyRole:
    def test_raises_clear_error_on_failure(self):
        with patch("boto3.client") as mock_client:
            mock_client.return_value.assume_role.side_effect = _client_error("AccessDenied")
            with pytest.raises(AssumeRoleError):
                verify_role("arn:aws:iam::222222222222:role/finops", "ext-abc")

    def test_succeeds_silently_when_role_is_assumable(self):
        with patch("boto3.client") as mock_client:
            mock_client.return_value.assume_role.return_value = {
                "Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s", "SessionToken": "t"}
            }
            verify_role("arn:aws:iam::222222222222:role/finops", "ext-abc")  # no raise


class TestAssumeRoleSession:
    def test_builds_a_session_from_the_temp_credentials(self):
        with patch("boto3.client") as mock_client, patch("boto3.Session") as mock_session:
            mock_client.return_value.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "AKIATEMP",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            }
            assume_role_session("arn:aws:iam::222222222222:role/finops", "ext-abc")

            mock_session.assert_called_once_with(
                aws_access_key_id="AKIATEMP",
                aws_secret_access_key="secret",
                aws_session_token="token",
            )
