import logging
import os
from tkinter import filedialog

import key_vault_api

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


def export_secrets(key_vault_name, secrets):
    # open file dialog
    user_home = os.path.expanduser('~')
    filename = filedialog.asksaveasfilename(initialdir=user_home, title="Select file",
                                            initialfile=key_vault_name + ".csv",
                                            filetypes=(("csv files", "*.csv"), ("all files", "*.*")))

    logger.info("Exporting secrets from key vault " + key_vault_name + " to file " + filename)

    # export secrets to file
    with open(filename, 'w') as outfile:
        for secret in secrets:
            secret_value = key_vault_api.get_secret_value(key_vault_name, secret)
            outfile.write(secret + "," + secret_value.replace("\n", "") + "\n")
