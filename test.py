import copy
import random


def get_secrets():
    # generate random secrets
    secrets = []
    secrets_count = random.randint(5, 50)
    for i in range(secrets_count):
        secret_name = "secret" + str(i + 1)
        secret_value = "value" + str(i + 1)

        secrets.append(secret_name)

    secrets.append("a_secret_with_a_very_loooooooooooooooooooooooooooooooooooooooong_name")

    return secrets


class TestKeyVault(str):
    name: str

    def __init__(self, name):
        self.name = name


def get_all_key_vaults():
    # generate subscriptions
    subscriptions = []
    for i in range(3):
        subscription = {
            'id': str(i),
            'name': "Subscription " + str(i)
        }

        # generate key vaults
        subscription_key_vaults = []
        key_vault_count = random.randint(1, 5)

        for j in range(key_vault_count):
            key_vault = TestKeyVault("keyvault" + str(i) + str(j))
            subscription_key_vaults.append(copy.deepcopy(key_vault))

        subscription['key_vaults'] = subscription_key_vaults

        subscriptions.append(subscription)

    return subscriptions


def get_secret_value():
    return "value"
