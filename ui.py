import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import secrets  # OWASP A2, cryptographically secure RNG for passwsrods
import string
import os
import logging
import logging.handlers
import uuid  # OWASP A1, UUIDv4 for non-predictable entry IDs
import storage
import model


# Directory creation with restricted permissions (0o700 = owner-only access)
log_dir = os.path.expanduser("~/.password_manager")
os.makedirs(log_dir, exist_ok=True, mode=0o700)
log_file = os.path.join(log_dir, "pm.log")
logger = logging.getLogger("password_manager")
logger.setLevel(logging.INFO)
fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3)
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(fh)


# At first run, asks for the master password from the user
def prompt_master_password(root) -> str:
    return simpledialog.askstring("Unlock Vault", "Master Password:", show='*', parent=root)


# Class for changing the master password
class ChangePasswordDialog(simpledialog.Dialog):
    def body(self, master):
        tk.Label(master, text="Old Password:").grid(row=0)
        tk.Label(master, text="New Password:").grid(row=1)
        tk.Label(master, text="Confirm New:").grid(row=2)
        self.old_var = tk.StringVar()
        self.new_var = tk.StringVar()
        self.conf_var = tk.StringVar()
        ttk.Entry(master, textvariable=self.old_var, show='*').grid(row=0, column=1)
        ttk.Entry(master, textvariable=self.new_var, show='*').grid(row=1, column=1)
        ttk.Entry(master, textvariable=self.conf_var, show='*').grid(row=2, column=1)
        return None

    def validate(self):
        if self.new_var.get() != self.conf_var.get():
            messagebox.showerror("Error", "New passwords do not match.")
            return False
        return True

    def apply(self):
        self.result = (self.old_var.get(), self.new_var.get())


# Implementation of the vault itself
class VaultApp:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()
        self.master_password = None
        self.vault = {}
        self.failed_attempts = 0  # OWASP A7, Tracking failed login tries
        self.unnamed_counter = 1
        self.authenticate()

    # Authenticating the user
    def authenticate(self):
        while True:
            pw = prompt_master_password(self.root)
            if pw is None:
                self.root.destroy()
                return

            try:
                if os.path.exists(storage.VAULT_FILENAME):
                    self.vault = storage.load_vault(storage.VAULT_FILENAME, pw)
                    max_num = 0
                    for entry in self.vault.values():
                        if entry['site'].startswith("Unnamed account "):
                            try:
                                num = int(entry['site'].split()[-1])
                                max_num = max(max_num, num)
                            except ValueError:
                                pass
                        if entry['username'].startswith("Unnamed user "):
                            try:
                                num = int(entry['username'].split()[-1])
                                max_num = max(max_num, num)
                            except ValueError:
                                pass
                    self.unnamed_counter = max_num + 1
                else:
                    if messagebox.askyesno("New Vault", "No vault found. Create a new one?", parent=self.root):
                        storage.save_vault(storage.VAULT_FILENAME, pw, {})
                    self.vault = {}

                self.master_password = pw
                self.setup_ui()
                self.root.deiconify()
                break
            except Exception as e:
                logger.warning("Failed unlock attempt: %s", e)
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    messagebox.showerror("Error", "Too many failed attempts.", parent=self.root)
                    self.root.destroy()
                    return
                messagebox.showerror("Error", "Incorrect password. Try again.", parent=self.root)
                continue

    # Setting up buttons and other UI elements
    def setup_ui(self):
        self.root.title("Password Vault")
        self.root.geometry("400x600")
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Import Vault...", command=self.import_vault)
        file_menu.add_command(label="Export Vault...", command=self.export_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Change Master Password", command=self.change_master_password)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_exit)
        menubar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menubar)

        self.tree = ttk.Treeview(self.root, columns=("username",), show="headings")
        self.tree.heading("username", text="Username")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.tree.bind("<Double-1>", lambda e: self.on_view_entry())
        self.tree.column("username", width=200)
        self.tree.heading("username", text="Username")

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        ttk.Button(btn_frame, text="Add", command=self.on_add).pack(fill=tk.X)
        ttk.Button(btn_frame, text="Edit", command=self.on_edit).pack(fill=tk.X)
        ttk.Button(btn_frame, text="Delete", command=self.on_delete).pack(fill=tk.X)
        ttk.Button(btn_frame, text="Generate", command=self.on_generate).pack(fill=tk.X)
        ttk.Button(btn_frame, text="Copy Password", command=self.on_copy).pack(fill=tk.X)
        self.refresh_tree()

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for key, entry in self.vault.items():
            self.tree.insert("", tk.END, iid=key, text=entry['site'], values=(entry['username'],))

    # Shows contents of an entry
    def on_view_entry(self):
        sel = self.tree.focus()
        if not sel:
            return
        entry = self.vault[sel]
        detail = f"Site: {entry['site']}\nUsername: {entry['username']}\nPassword: {entry['password']}\nNotes: {entry.get('notes','')}"
        messagebox.showinfo("Entry Detail", detail, parent=self.root)

    # When user presses the add button
    def on_add(self):
        data = self.entry_dialog()
        if data:
            site = data.get('site', '').strip()
            username = data.get('username', '').strip()

            needs_placeholder = False
            if not site:
                needs_placeholder = True
            if not username:
                needs_placeholder = True

            if needs_placeholder:
                current_number = self.unnamed_counter
                self.unnamed_counter += 1

                if not site:
                    data['site'] = f"Unnamed account {current_number}"
                if not username:
                    data['username'] = f"Unnamed user {current_number}"

            uid = str(uuid.uuid4())
            self.vault[uid] = data
            storage.save_vault(storage.VAULT_FILENAME, self.master_password, self.vault)
            self.refresh_tree()

    # When user presses the edit button
    def on_edit(self):
        sel = self.tree.focus()
        if not sel:
            return
        data = self.entry_dialog(self.vault[sel])
        if data:
            self.vault[sel] = data
            storage.save_vault(storage.VAULT_FILENAME, self.master_password, self.vault)
            self.refresh_tree()

    # When user presses the delete button
    def on_delete(self):
        sel = self.tree.focus()
        if not sel:
            return
        if messagebox.askyesno("Delete", "Are you sure?", parent=self.root):
            del self.vault[sel]
            storage.save_vault(storage.VAULT_FILENAME, self.master_password, self.vault)
            self.refresh_tree()

    # Editing entry
    def entry_dialog(self, entry=None):
        dlg = tk.Toplevel(self.root)
        dlg.title("Edit Entry" if entry else "Add Entry")
        labels = ["Site", "Username", "Password", "Notes"]
        vars = {label: tk.StringVar(value=entry.get(label.lower(), "") if entry else "") for label in labels}

        for i, label in enumerate(labels):
            ttk.Label(dlg, text=label + ":").grid(row=i, column=0)
            show = "*" if label == "Password" else ""
            ttk.Entry(dlg, textvariable=vars[label], show=show).grid(row=i, column=1)

        def generate_password():
            if (pwd := self.generate_password_dialog()) is not None:
                vars["Password"].set(pwd)  # Directly update the password field

        ttk.Button(dlg, text="Generate", command=generate_password).grid(row=2, column=2)

        def on_ok():
            data = {k.lower(): v.get() for k, v in vars.items()}
            if not data.get('password'):
                messagebox.showerror("Error", "Password cannot be empty!", parent=dlg)
                return
            dlg.result = data
            dlg.destroy()

        def on_cancel():
            dlg.result = None
            dlg.destroy()

        ttk.Button(dlg, text="OK", command=on_ok).grid(row=4, column=0)
        ttk.Button(dlg, text="Cancel", command=on_cancel).grid(row=4, column=1)
        dlg.grab_set()
        dlg.wait_window()
        return getattr(dlg, 'result', None)

    # Generating a random password and copying it to clipboard
    def on_generate(self):
        pwd = self.generate_password_dialog()
        if pwd:
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            messagebox.showinfo("Password Generated", "Password copied to clipboard for 30 seconds.", parent=self.root)
            self.root.after(30000, lambda: self.root.clipboard_clear())

    # User chooses the length and symbols for the generated password
    def generate_password_dialog(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Generate Password")
        dlg.geometry("210x220")

        main_frame = ttk.Frame(dlg)
        main_frame.pack(padx=10, pady=10, fill='both', expand=True)

        # Length selection
        length_var = tk.IntVar(value=16)
        ttk.Label(main_frame, text="Length:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        ttk.Spinbox(main_frame, from_=8, to=64, textvariable=length_var, width=5).grid(
            row=0, column=1, padx=5, pady=5, sticky="w")

        # Checkboxes frame
        check_frame = ttk.LabelFrame(main_frame, text="Character Sets")
        check_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        opts = {
            'Uppercase': tk.BooleanVar(value=True),
            'Lowercase': tk.BooleanVar(value=True),
            'Digits': tk.BooleanVar(value=True),
            'Symbols': tk.BooleanVar(value=False),
        }

        for i, (text, var) in enumerate(opts.items()):
            ttk.Checkbutton(check_frame, text=text, variable=var).grid(
                row=i // 2, column=i % 2,
                padx=5, pady=2, sticky="w")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        def do_generate():
            chars = ''
            if opts['Uppercase'].get(): chars += string.ascii_uppercase
            if opts['Lowercase'].get(): chars += string.ascii_lowercase
            if opts['Digits'].get():    chars += string.digits
            if opts['Symbols'].get():   chars += string.punctuation
            if not chars:
                messagebox.showerror("Error", "Select at least one character set.", parent=dlg)
                return
            # OWASP A2 with the secrets module instead of random
            pwd = ''.join(secrets.choice(chars) for _ in range(length_var.get()))
            dlg.result = pwd
            dlg.destroy()

            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)

        ttk.Button(btn_frame, text="Generate", command=do_generate).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancel",
                   command=lambda: (setattr(dlg, 'result', None), dlg.destroy())).pack(side=tk.LEFT, padx=10)

        dlg.grab_set()
        dlg.wait_window()
        return getattr(dlg, 'result', None)

    # Copies the password to clipboard
    def on_copy(self):
        sel = self.tree.focus()
        if not sel: return
        pwd = self.vault[sel]['password']
        self.root.clipboard_clear()
        self.root.clipboard_append(pwd)
        # OWASP A3, clearing the clipboard after 30 seconds:
        messagebox.showinfo("Password Copied", "Password copied to clipboard for 30 seconds.", parent=self.root)
        self.root.after(30000, lambda: self.root.clipboard_clear())

    # More implementation for changing the master password
    def change_master_password(self):
        dlg = ChangePasswordDialog(self.root, title="Change Master Password")
        old_pw, new_pw = getattr(dlg, 'result', (None, None)) or (None, None)
        if not old_pw or not new_pw:
            return
        try:
            storage.load_vault(storage.VAULT_FILENAME, old_pw)
            self.master_password = new_pw
            storage.save_vault(storage.VAULT_FILENAME, self.master_password, self.vault)
            messagebox.showinfo("Success", "Master password changed.", parent=self.root)
        except Exception as e:
            logger.error("Failed to change master password: %s", e)
            messagebox.showerror("Error", "Failed to change master password: " + str(e), parent=self.root)

    # Importing a vault file from an external source
    def import_vault(self):
        path = filedialog.askopenfilename(title="Select vault file", filetypes=[("Vault","*.dat"),("All","*.*")])
        if not path: return
        pw = simpledialog.askstring("Password","Master password for imported vault:", show='*', parent=self.root)
        if not pw: return
        try:
            data = storage.load_vault(path, pw)
            if messagebox.askyesno("Import","Replace current vault?", parent=self.root):
                self.vault = data
                self.master_password = pw
                storage.save_vault(storage.VAULT_FILENAME, pw, self.vault)
                self.refresh_tree()
        except Exception as e:
            messagebox.showerror("Error","Failed to import: " + str(e), parent=self.root)

    # Exporting the vault file to external source
    def export_vault(self):
        path = filedialog.asksaveasfilename(title="Export vault to", defaultextension=".dat", filetypes=[("Vault","*.dat")])
        if not path: return
        try:
            with open(storage.VAULT_FILENAME, "rb") as src, open(path, "wb") as dst:
                dst.write(src.read())
            messagebox.showinfo("Exported", "Vault exported successfully.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Error","Failed to export: " + str(e), parent=self.root)

    def on_exit(self):
        self.root.quit()
