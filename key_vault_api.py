from azure.core.exceptions import AzureError
from azure.keyvault.secrets import SecretClient
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
import os
from dotenv import load_dotenv
import logging
import test
import subprocess
import json

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logger = logging.getLogger(__name__)

load_dotenv()

proxy = os.getenv('PROXY')
test_mode = os.getenv('TEST') == 'True'

if proxy:
    logger.info("Using proxy: " + proxy)

    os.environ['HTTP_PROXY'] = os.environ['http_proxy'] = proxy
    os.environ['HTTPS_PROXY'] = os.environ['https_proxy'] = proxy
    os.environ['NO_PROXY'] = os.environ['no_proxy'] = '127.0.0.1,localhost,.local'


def get_secrets(key_vault_name):
    logger.info("Getting secrets from KeyVault: " + str(key_vault_name))

    if test_mode:
        return test.get_secrets()

    key_vault_url = f"https://{key_vault_name}.vault.azure.net"

    credential = AzureCliCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)

    secret_properties = client.list_properties_of_secrets()

    secrets = []
    for secret_property in secret_properties:
        secret_name = secret_property.name
        # secret_value = client.get_secret(secret_name).value

        secrets.append(secret_name)

    logger.info("Found " + str(len(secrets)) + " secrets in KeyVault " + key_vault_name)

    return secrets


def get_secret_value(key_vault_name, secret_name):
    logger.info("Getting secret " + secret_name + " from KeyVault " + key_vault_name)

    if test_mode:
        return test.get_secret_value()

    key_vault_url = f"https://{key_vault_name}.vault.azure.net"

    credential = AzureCliCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)

    secret_value = client.get_secret(secret_name).value

    logger.info("Found secret " + secret_name + " in KeyVault " + key_vault_name)

    return secret_value


def get_all_key_vaults():
    logger.info("Loading all key vaults")

    if test_mode:
        return test.get_all_key_vaults()

    credential = AzureCliCredential()

    # workaround to get subscription id because subscription_client.subscriptions.list() does not work
    subscriptions = json.loads(subprocess.check_output('az account list', shell=True).decode('utf-8'))

    # if no subscriptions were found, throw error
    if len(subscriptions) == 0:
        raise Exception("No subscription found")

    subs_with_key_vaults = []

    for sub in subscriptions:

        sub_name = sub['name']

        try:

            sub_id = sub['id']

            # obtain the management object for resources.
            resource_client = ResourceManagementClient(credential, sub_id)

            # get all resources
            resources = resource_client.resources.list()

            # filter resources by resource type key vault
            sub_key_vaults = [resource for resource in resources if resource.type == "Microsoft.KeyVault/vaults"]

            # remove all key vaults containing "prod" in name from the list
            sub_key_vaults = [key_vault for key_vault in sub_key_vaults if "prod" not in key_vault.name]

            # sort by name
            sub_key_vaults = sorted(sub_key_vaults, key=lambda x: x.name)

            sub['key_vaults'] = sub_key_vaults
            subs_with_key_vaults.append(sub)

            logger.info("Found " + str(len(sub_key_vaults)) + " key vaults " + " in subscription " + sub_id)

        except AzureError as ex:
            logger.warning("Error getting key vaults for subscription " + sub_name + ": " + str(ex))
            continue

    return subs_with_key_vaults


if __name__ == '__main__':
    subscriptions = get_all_key_vaults()

    for sub in subscriptions:

        print(sub['name'])

        keyvaults = sub['key_vaults']

        for kv in keyvaults:
            print(kv.name)
