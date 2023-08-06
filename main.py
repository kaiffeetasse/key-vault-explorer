import logging
import os
import tkinter as tk
from tkinter import BOTH, RIGHT, END, LEFT, TOP, ttk
import pyperclip
from PIL import Image, ImageTk

import exporter_util
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
export_button = tk.Button(window)
original_secrets = []
current_key_vault_name = ""

listbox_added = False


def add_listbox():
    # add button to export secrets
    global export_button
    export_button = tk.Button(window, text="Export secrets",
                              command=lambda: exporter_util.export_secrets(current_key_vault_name, original_secrets))
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

    # listbox.config(width=0)

    # make the listbox height max. 20 items
    if len(items) < 20:
        listbox.config(height=len(items))
    else:
        listbox.config(height=20)


select_key_vault_label = tk.Label(window, text="Select key vault")


def key_vault_select_callback(*args):
    key_vault_name = ""
    global listbox_added

    try:

        global tree
        key_vault_name = tree.item(tree.selection())['text']

        secrets = key_vault_api.get_secrets(key_vault_name)
        global original_secrets
        original_secrets = secrets

        global current_key_vault_name
        current_key_vault_name = key_vault_name

        if not listbox_added:
            # remove the select key vault label
            select_key_vault_label.pack_forget()
            add_listbox()

        set_listbox_items(secrets)

        # clear the filter textbox if it contains text
        if entry.get() != "" and entry.get() != "filter secrets":
            entry.delete(0, END)

    except Exception as e:
        logger.error("Could not load key vault secrets for vault " + str(key_vault_name))

        # set label text to error message
        select_key_vault_label.config(text="Could not load key vault secrets for vault " + str(key_vault_name)
                                           + " (" + str(e) + ")")

        # remove the listbox and export button
        listbox.pack_forget()
        global export_button
        export_button.pack_forget()
        listbox_added = False

        # show the label centered
        select_key_vault_label.pack(side=tk.TOP, fill=BOTH, expand=True)


variable = tk.StringVar(window)


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


tree = None


def add_key_vaults_to_sidebar(side_bar_frame):
    subscriptions = key_vault_api.get_all_key_vaults()

    if len(subscriptions) == 0:
        select_key_vault_label.config(text="No key vaults found")
        select_key_vault_label.pack(side=tk.TOP, fill=BOTH, expand=True)
        return

    global tree
    tree = ttk.Treeview(side_bar_frame)

    for sub in subscriptions:

        tree.insert('', 0, sub['name'], text=sub['name'], open=True)

        key_vaults = sub['key_vaults']

        for key_vault in key_vaults:
            tree.insert(sub['name'], 0, key_vault.name, text=key_vault.name)

            # add double click listener
            tree.bind('<Double-Button>', key_vault_select_callback)

    tree.pack(side=tk.TOP, fill=BOTH, expand=True)


def save_window_size(*args):
    with open("key-vault-exporter.conf", "w") as conf:
        conf.write(window.geometry())


def on_close():
    save_window_size()
    window.destroy()


def init_window():
    # add cmd+f listener
    # mac
    window.bind('<Command-f>', lambda event: entry.focus_set())

    # windows
    window.bind('<Control-f>', lambda event: entry.focus_set())

    if os.path.isfile("key-vault-exporter.conf"):
        with open("key-vault-exporter.conf", "r") as conf:
            window_config = conf.read()

            size_x = int(window_config.split("x")[0])
            size_y = int(window_config.split("x")[1].split("+")[0])

            pos_x = int(window_config.split("+")[1])
            pos_y = int(window_config.split("+")[2])

            if pos_x < 0:
                pos_x = 0

            window_config = str(size_x) + "x" + str(size_y) + "+" + str(pos_x) + "+" + str(pos_y)

            window.geometry(window_config)
    else:
        # default window position and size
        window.geometry('500x500+0+0')

    window.bind("<Configure>", save_window_size)
    window.protocol("WM_DELETE_WINDOW", on_close)


if __name__ == '__main__':
    menu_bar_frame = tk.Frame(window)

    # add_key_vault_dropdown(menu_bar_frame)
    add_filter_textbox(menu_bar_frame)

    menu_bar_frame.pack(side=tk.TOP, fill=BOTH)

    side_bar_frame = tk.Frame(window)
    add_key_vaults_to_sidebar(side_bar_frame)
    side_bar_frame.pack(side=tk.LEFT, fill=BOTH)

    # add select_key_vault_label vertically centered
    select_key_vault_label.pack(side=tk.TOP, fill=BOTH, expand=True)

    init_window()

    window.mainloop()
