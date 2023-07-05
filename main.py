import logging
import tkinter as tk
from tkinter import BOTH, RIGHT, END, LEFT
import pyperclip
from PIL import Image, ImageTk

import key_vault_api
from entry_with_placeholder import EntryWithPlaceholder

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)

logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

window = tk.Tk()

# set app icon
ico = Image.open('icon.png')
photo = ImageTk.PhotoImage(ico)
window.wm_iconphoto(False, photo)

# set app name
window.title("Key Vault Explorer")

listbox = tk.Listbox(window)
original_secrets = []

listbox_added = False


def add_listbox():
    listbox.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar = tk.Scrollbar(window)
    scrollbar.pack(side=RIGHT, fill=BOTH)

    listbox.config(yscrollcommand=scrollbar.set)

    listbox.config(width=0)

    scrollbar.config(command=listbox.yview)

    listbox.bind('<Double-Button>', listbox_double_click)

    global listbox_added
    listbox_added = True


def get_secret_value(entry):
    for secret in original_secrets:
        if secret['name'] == entry:
            return secret['value']


def listbox_double_click(event):
    entry = listbox.get(listbox.curselection())

    logger.info("Copying secret " + entry)

    secret_value = get_secret_value(entry)

    pyperclip.copy(secret_value)


def set_listbox_items(items):
    listbox.delete(0, END)

    for item in items:
        listbox.insert(END, item['name'])

    listbox.config(width=0)

    # make the listbox height max. 20 items
    if len(items) < 20:
        listbox.config(height=len(items))
    else:
        listbox.config(height=20)

def callback(*args):
    key_vault_name = variable.get()

    secrets = key_vault_api.get_secrets(key_vault_name)
    global original_secrets
    original_secrets = secrets

    if not listbox_added:
        add_listbox()

    set_listbox_items(secrets)


variable = tk.StringVar(window)


def add_dropdown(frame):
    variable.set("select key vault")

    variable.trace("w", callback)

    key_vaults = key_vault_api.get_all_key_vaults()

    w = tk.OptionMenu(window, variable, *key_vaults)

    w.pack(in_=frame, side=tk.LEFT)


def filter_listbox(entry):
    search_query = entry.get()

    # clear the listbox
    listbox.delete(0, END)

    global original_secrets

    # filter the secrets
    filtered_secrets = list(filter(lambda secret: search_query in secret['name'], original_secrets))

    # add the filtered secrets to the listbox
    for filtered_secret in filtered_secrets:
        listbox.insert(END, filtered_secret['name'])


def add_filter_textbox(frame):
    entry = EntryWithPlaceholder(window, "filter secrets")
    entry.pack(in_=frame, side=tk.LEFT)

    # add callback
    entry.bind('<KeyRelease>', lambda event: filter_listbox(entry))


if __name__ == '__main__':
    menu_bar_frame = tk.Frame(window)
    add_dropdown(menu_bar_frame)
    add_filter_textbox(menu_bar_frame)

    menu_bar_frame.pack(side=tk.TOP, fill=BOTH)

    window.mainloop()
