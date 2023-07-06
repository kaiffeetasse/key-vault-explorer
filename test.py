def get_secrets():
    # generate random secrets
    secrets = []
    for i in range(25):
        secret_name = "secret" + str(i + 1)
        secret_value = "value" + str(i + 1)

        secrets.append({"name": secret_name, "value": secret_value})

    secrets.append({"name": "a_secret_with_a_very_loooooooooooooooooooooooooooooooooooooooong_name", "value": "value"})

    return secrets


def get_all_key_vaults():
    # generate random key vaults
    key_vaults = []
    for i in range(5):
        key_vault_name = "key_vault" + str(i)

        key_vaults.append(key_vault_name)

    return key_vaults
