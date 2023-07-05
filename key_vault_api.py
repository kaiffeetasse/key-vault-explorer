from azure.keyvault.secrets import SecretClient
from azure.identity import AzureCliCredential
import os
from dotenv import load_dotenv
import logging

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)

load_dotenv()

proxy = os.getenv('PROXY')

if proxy:
    logger.info("Using proxy: " + proxy)

    os.environ['HTTP_PROXY'] = os.environ['http_proxy'] = proxy
    os.environ['HTTPS_PROXY'] = os.environ['https_proxy'] = proxy
    os.environ['NO_PROXY'] = os.environ['no_proxy'] = '127.0.0.1,localhost,.local'


def get_secrets(key_vault_name):
    logger.info("Getting secrets from KeyVault " + key_vault_name)

    key_vault_url = f"https://{key_vault_name}.vault.azure.net"

    credential = AzureCliCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)

    secret_properties = client.list_properties_of_secrets()

    secrets = []
    for secret_property in secret_properties:
        secret_name = secret_property.name
        secret_value = client.get_secret(secret_name).value

        secrets.append({"name": secret_name, "value": secret_value})

    logger.info("Found " + str(len(secrets)) + " secrets in KeyVault " + key_vault_name)

    return secrets


def get_all_key_vaults():

    logger.info("Loading all key vaults")

    from azure.mgmt.resource import ResourceManagementClient
    credential = AzureCliCredential()

    # workaround to get subscription id because subscription_client.subscriptions.list() does not work
    import subprocess
    import json
    subscriptions = json.loads(subprocess.check_output('az account list', shell=True).decode('utf-8'))

    sub_id = subscriptions[0]['id']

    # from azure.mgmt.subscription import SubscriptionClient
    # sub_client = SubscriptionClient(credential)
    # sub_id = list(sub_client.subscriptions.list())[0].subscription_id

    # Obtain the management object for resources.
    resource_client = ResourceManagementClient(credential, sub_id)

    # get all resources
    resources = resource_client.resources.list()

    # filter resources by resource type key vault
    key_vaults = [resource for resource in resources if resource.type == "Microsoft.KeyVault/vaults"]

    # remove all key vaults containing "prod" in name from the list
    key_vaults = [key_vault for key_vault in key_vaults if "prod" not in key_vault.name]

    logger.info("Found " + str(len(key_vaults)) + " key vaults")

    return [key_vault.name for key_vault in key_vaults]


if __name__ == '__main__':
    get_all_key_vaults()
