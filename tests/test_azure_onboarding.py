from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

from core.azure_onboarding import (
    AzureConnectError,
    build_azure_credential,
    generate_setup_instructions,
    verify_service_principal,
)


class TestGenerateSetupInstructions:
    def test_names_both_required_roles(self):
        instructions = generate_setup_instructions()
        assert "Reader" in instructions
        assert "Cost Management Reader" in instructions

    def test_includes_the_creation_command(self):
        instructions = generate_setup_instructions()
        assert "az ad sp create-for-rbac" in instructions
        assert "azure-credentials" in instructions


class TestBuildAzureCredential:
    def test_builds_with_given_values(self):
        with patch("core.azure_onboarding.ClientSecretCredential") as MockCred:
            build_azure_credential("tid", "cid", "secret")
        MockCred.assert_called_once_with(tenant_id="tid", client_id="cid", client_secret="secret")


class TestVerifyServicePrincipal:
    def test_raises_clear_error_on_auth_failure(self):
        with patch("core.azure_onboarding.build_azure_credential", return_value=MagicMock()), \
             patch("core.azure_onboarding.ResourceManagementClient") as MockClient:
            MockClient.return_value.resource_groups.list.side_effect = ClientAuthenticationError("bad creds")
            with pytest.raises(AzureConnectError):
                verify_service_principal("tid", "cid", "secret", "sub")

    def test_raises_clear_error_on_missing_permissions(self):
        with patch("core.azure_onboarding.build_azure_credential", return_value=MagicMock()), \
             patch("core.azure_onboarding.ResourceManagementClient") as MockClient:
            MockClient.return_value.resource_groups.list.side_effect = HttpResponseError("forbidden")
            with pytest.raises(AzureConnectError):
                verify_service_principal("tid", "cid", "secret", "sub")

    def test_succeeds_silently_when_reader_access_confirmed(self):
        with patch("core.azure_onboarding.build_azure_credential", return_value=MagicMock()), \
             patch("core.azure_onboarding.ResourceManagementClient") as MockClient:
            MockClient.return_value.resource_groups.list.return_value = iter([MagicMock()])
            verify_service_principal("tid", "cid", "secret", "sub")  # no raise

    def test_succeeds_even_with_zero_resource_groups(self):
        """An empty subscription is still a valid, verified connection --
        Reader access confirmed, just nothing to list yet."""
        with patch("core.azure_onboarding.build_azure_credential", return_value=MagicMock()), \
             patch("core.azure_onboarding.ResourceManagementClient") as MockClient:
            MockClient.return_value.resource_groups.list.return_value = iter([])
            verify_service_principal("tid", "cid", "secret", "sub")  # no raise
