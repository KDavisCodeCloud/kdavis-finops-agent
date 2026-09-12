"""Azure Service Principal onboarding: setup instructions, and credential
verification/building.

Mirrors core/aws_onboarding.py's shape, but Azure's model is materially
simpler on one axis and different on another:

- Simpler: Azure's built-in `Reader` + `Cost Management Reader` roles
  already cover exactly what AzureProvider.collect() needs -- there's no
  custom JSON policy to hand-build like AWS's build_permissions_policy().
- Different: unlike AWS's assume-role flow (no persisted customer
  secret -- external_id is not sensitive), a Service Principal's
  client_secret IS a real secret that must be encrypted at rest (see
  security/encryption.py) once verified and stored.
"""

import logging

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import ClientSecretCredential
from azure.mgmt.resource.resources import ResourceManagementClient

log = logging.getLogger(__name__)

_REQUIRED_ROLES = ("Reader", "Cost Management Reader")


class AzureConnectError(Exception):
    """Raised when the customer's Service Principal can't be verified --
    wraps the underlying Azure error message."""


def build_azure_credential(tenant_id: str, client_id: str, client_secret: str) -> ClientSecretCredential:
    return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)


def generate_setup_instructions(subscription_id_placeholder: str = "<your-subscription-id>") -> str:
    """Human-readable Azure CLI steps a customer runs once, in their own
    tenant, to create the Service Principal this service will use.

    Unlike AWS's trust/permissions policy (JSON pasted into the AWS
    console), this is CLI commands -- there's no per-tenant value (like
    AWS's external_id) baked into these instructions, so this function
    takes no tenant-specific arguments.
    """
    roles = " and ".join(f'"{r}"' for r in _REQUIRED_ROLES)
    return (
        "In Azure: run `az ad sp create-for-rbac --name finops-agent-readonly "
        "--skip-assignment` to create a Service Principal -- note the "
        "appId (client_id), password (client_secret), and tenant. Then "
        f"assign it {roles} at your subscription scope:\n"
        "  az role assignment create --assignee <appId> --role \"Reader\" "
        f"--scope /subscriptions/{subscription_id_placeholder}\n"
        "  az role assignment create --assignee <appId> --role \"Cost Management Reader\" "
        f"--scope /subscriptions/{subscription_id_placeholder}\n"
        "Then call PATCH /tenants/{tenant_id}/azure-credentials with the "
        "tenant_id, client_id, client_secret, and subscription_id."
    )


def verify_service_principal(tenant_id: str, client_id: str, client_secret: str, subscription_id: str) -> None:
    """Raises AzureConnectError if the Service Principal can't authenticate
    or lacks Reader access. Doesn't return anything -- verification only,
    the scan endpoint builds credentials fresh each time."""
    credential = build_azure_credential(tenant_id, client_id, client_secret)
    try:
        client = ResourceManagementClient(credential, subscription_id)
        # Lightest real call that proves both authentication and Reader
        # access -- list() is lazy, next() forces one page of real work.
        next(iter(client.resource_groups.list()), None)
    except ClientAuthenticationError as exc:
        raise AzureConnectError(f"Authentication failed: {exc}") from exc
    except HttpResponseError as exc:
        raise AzureConnectError(f"Could not verify access: {exc}") from exc
