COMP.SEC.300 Project - Password Manager
=======================================

This Python program is a basic local password manager created as a course project (COMP.SEC.300). Tested and implemented using Windows 11 and Python 3.9.

General Description
-
This password manager is created using Python as the programming language, and is used to store,
generate and manage user credentials. These credentials include site name, username, password and
notes about the site/username. All credentials are stored in an encrypted vault, that can be
exported or imported if user so pleases. User interface is implemented using TKinter. 

Some generally useful information regarding the program:
1. User has buttons for adding, editing and deleting entries.
2. User can generate a randomized password for any use.
3. Automatically generated passwords are copied to clipboard, which will be cleared after 30
seconds if not pasted.
4. User can click "File" in the main window to change master password and import/export vaults
5. If user does not place any site name or username when adding an entry, the program adds a
default placeholder for it. 
6. A CLI argument (--headless-test) is included for future improvement (not yet implemented).
7. Vaults are saved to ~/.password_manager/vault.dat with strict file permissions. 

How to use
-

To launch the program:
1. Head to the directory containing the source code.
2. Make sure all dependencies are installed (pip install)
3. Run the program using command "python main.py"
4. When ran for the first time, the program prompts the user with "No vault found. Create
a new one?", click yes.

Project structure
-
The project consists of five files:
1. ui.py: Manages Tkinter GUI, entry dialogs and other user interactions.
2. crypto.py: Implements AES-GCM encryption/decryption and PBKDF2 key derivation.
3. storage.py, Handles vault file I/O, encryption/decryption, and atomic writes.
4. model.py: Defines a dataclass entry for credential storage.
5. main.py: Initializes the app and parses CLI arguments.

The basic data flow is:
1. User inputs master password → PBKDF2 derives a key → AES-GCM encrypts/decrypts vault data.
2. Vault data is stored as JSON, encrypted, and written to disk with atomic operations to prevent corruption.

Secure programming solutions (OWASP top 10)
-

A02: Cryptographic failures
1. PBKDF2 key stretching: crypto.derive_key uses 200 000 iterations with SHA-256 to resist
brute-forcing (computationally very expensive to crack). Also meets standards like NIST recommendation.
2. AES-GCM encryption: a random 12-byte nonce and 16-byte salt makes the data unreadable without the correct key. Salts and nonces
also defeats rainbow tables and replay attacks.
3. Passwords are generated using secrets.choice, which makes the generated passwords very resistant to brute-forcing and guessing.

A03: Injection
1. User inputs are treated as strings, not executable code. This makes sure that no changes can made through the user inputs.

A04: Insecure design
1. Master password is required to decrypt the vault. This makes sure unauthorized access is not possible.
2. Copied passwords are auto-cleared after 30 seconds if not pasted before that, which reduces the risk of apps or malware harvesting the password.

A05: Security misconfiguration
1. File permissions: Vault/log directories use 0c700; files use 0o600 to restrict access to prevent other users/processes on the same
machine from reading sensitive data.
2. Atomic writes: storage.save_vault writes to a temp file first to prevent partial writes on failure, which avoids data corruption or partial exposure.

A06: Vulnerable components
1. A frequently updated and up-to-date Cryptography module instead of a deprecated library like pycrypto.

A07: Identification and Authentication Failures 
1. Tracks the failed attempts of the master password, and 3 failed attempts quits the program, which prevents unauthorized use.

A09: Monitoring failures
1. Using the atomic renaming in storage.py makes sure a file operation is completed fully or not at all.

Unimplemented features and known issues
- 

Unimplemented:
1. Headless testing: The --headless-test flag is not functional
2. Two-factor authentication or backup keys are not suppoorted

Vulnerabilities:
1. Master passwords and decrypted vaults are stored in memory, so a memory dump could expose
the stored values
2. Even with the 30-second clipboard erasure, the password could be accessible to other processes.
3. Passwords won't be erased from clipboard automatically if user copies and pastes the password within
the 30-second time window.

Possible future improvements
-

1. Overwriting sensitive strings in memory (hard in Python because of immutability)
2. Allowing users to change PBKDF2 iterations through a settings menu
3. Logging all access/modification attempts with timestamps
4. Backup or recovery options