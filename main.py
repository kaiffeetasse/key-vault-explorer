import logging
import os
import tkinter as tk
from tkinter import BOTH, RIGHT, END, LEFT, TOP
from tkinter import filedialog
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
current_key_vault_name = ""

listbox_added = False


def export_secrets():
    # open file dialog
    user_home = os.path.expanduser('~')
    filename = filedialog.asksaveasfilename(initialdir=user_home, title="Select file",
                                            initialfile=current_key_vault_name + ".csv",
                                            filetypes=(("csv files", "*.csv"), ("all files", "*.*")))

    logger.info("Exporting secrets from key vault " + current_key_vault_name + " to file " + filename)

    # export secrets to file
    with open(filename, 'w') as outfile:
        for secret in original_secrets:
            secret_value = key_vault_api.get_secret_value(current_key_vault_name, secret)
            outfile.write(secret + "," + secret_value.replace("\n", "") + "\n")


def add_listbox():
    # add button to export secrets
    export_button = tk.Button(window, text="Export secrets", command=export_secrets)
    export_button.pack(side=TOP, anchor='w')

    # add scrollable listbox
    listbox.pack(side=LEFT, fill=BOTH, expand=True)
    scrollbar = tk.Scrollbar(window)
    scrollbar.pack(side=RIGHT, fill=BOTH)

    listbox.config(yscrollcommand=scrollbar.set)

    scrollbar.config(command=listbox.yview)

    listbox.bind('<Double-Button>', listbox_double_click_callback)

    global listbox_added
    listbox_added = True


def listbox_double_click_callback(event):
    entry = listbox.get(listbox.curselection())

    logger.info("Copying secret " + entry)

    secret_value = key_vault_api.get_secret_value(current_key_vault_name, entry)

    pyperclip.copy(secret_value)


def set_listbox_items(items):
    listbox.delete(0, END)

    for item in items:
        listbox.insert(END, item)

    listbox.config(width=0)

    # make the listbox height max. 20 items
    if len(items) < 20:
        listbox.config(height=len(items))
    else:
        listbox.config(height=20)


def key_vault_select_callback(*args):
    key_vault_name = variable.get()

    secrets = key_vault_api.get_secrets(key_vault_name)
    global original_secrets
    original_secrets = secrets

    global current_key_vault_name
    current_key_vault_name = key_vault_name

    if not listbox_added:
        add_listbox()

    set_listbox_items(secrets)

    # clear the filter textbox if it contains text
    if entry.get() != "" and entry.get() != "filter secrets":
        entry.delete(0, END)


variable = tk.StringVar(window)


def add_key_vault_dropdown(frame):
    variable.set("select key vault")

    variable.trace("w", key_vault_select_callback)

    key_vaults = key_vault_api.get_all_key_vaults()

    w = tk.OptionMenu(window, variable, *key_vaults)

    w.pack(in_=frame, side=tk.LEFT)


def filter_listbox(entry):
    search_query = entry.get()

    # clear the listbox
    listbox.delete(0, END)

    global original_secrets

    # filter the secrets
    filtered_secrets = list(filter(lambda secret: search_query in secret, original_secrets))

    # add the filtered secrets to the listbox
    for filtered_secret in filtered_secrets:
        listbox.insert(END, filtered_secret)


entry = EntryWithPlaceholder(window, "filter secrets")


def add_filter_textbox(frame):
    global entry
    entry = EntryWithPlaceholder(window, "filter secrets")
    entry.pack(in_=frame, side=tk.LEFT, fill=BOTH, expand=True)

    # add callback
    entry.bind('<KeyRelease>', lambda event: filter_listbox(entry))

    # add (x) button next to the textbox to clear the textbox
    clear_button = tk.Button(window, text="x", command=lambda: clear_filter_textbox())
    clear_button.pack(in_=frame, side=tk.RIGHT)


def clear_filter_textbox():
    text = entry.get()
    if text == "" or text == "filter secrets":
        return

    entry.delete(0, END)

    # apply filter
    filter_listbox(entry)


if __name__ == '__main__':
    menu_bar_frame = tk.Frame(window)
    add_key_vault_dropdown(menu_bar_frame)
    add_filter_textbox(menu_bar_frame)

    menu_bar_frame.pack(side=tk.TOP, fill=BOTH)

    # add cmd+f listener
    # mac
    window.bind('<Command-f>', lambda event: entry.focus_set())

    # windows
    window.bind('<Control-f>', lambda event: entry.focus_set())

    window.mainloop()
