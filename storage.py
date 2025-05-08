import os
import json
import tempfile
import crypto

VAULT_FILENAME = os.path.expanduser("~/.password_manager/vault.dat")


# Loads the vault from file
def load_vault(path: str, master_password: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    plaintext = crypto.decrypt(data, master_password)
    return json.loads(plaintext.decode())


def save_vault(path: str, master_password: str, vault: dict):
    plaintext = json.dumps(vault, indent=2).encode()
    data = crypto.encrypt(plaintext, master_password)
    dirpath = os.path.dirname(path)
    os.makedirs(dirpath, exist_ok=True, mode=0o700)  # OWASP A3: directory permissions
    # Atomic write pattern (file operations are completed fully or not at all):
    fd, tmp_path = tempfile.mkstemp(dir=dirpath)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.chmod(tmp_path, 0o600)  # Restrictive file permissions (OWASP A3)
        os.replace(tmp_path, path)  # Atomic rename operation (OWASP A9-ish implementation)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
