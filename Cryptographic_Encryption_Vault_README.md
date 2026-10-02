# Cryptographic Encryption Vault

A Python-based **Cryptographic Encryption Vault** that encrypts and decrypts
multiple files inside a directory using **Fernet authenticated encryption**
and **PBKDF2-HMAC-SHA256** key derivation.

## Objective

Build a multi-file directory encryption tool with secure key-management
practices.

## Features

- Recursively scans directories for files
- Encrypts files using Fernet
- Decrypts encrypted `.enc` files
- Uses a master passphrase for key derivation
- Generates a random salt
- Uses PBKDF2-HMAC-SHA256
- Displays encryption/decryption execution results
- Provides a local recovery-key backup

## Requirements

- Python 3.x
- `cryptography` library

Install the required library:

```bash
pip install cryptography
```

## Vault Script

Save the following code as **`vault.py`**:

```python
import argparse
import base64
import getpass
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

SALT_FILE = ".vault_salt"
BACKUP_FILE = ".vault_key_backup.txt"


def derive_key(password, salt):
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000,
        32
    )
    return base64.urlsafe_b64encode(raw_key)


def main():
    parser = argparse.ArgumentParser(
        description="Cryptographic Directory Encryption Vault"
    )

    parser.add_argument(
        "mode",
        choices=["encrypt", "decrypt"]
    )

    parser.add_argument(
        "directory",
        help="Directory containing files"
    )

    args = parser.parse_args()
    vault = Path(args.directory).resolve()

    if not vault.is_dir():
        print("Directory not found:", vault)
        return 1

    password = getpass.getpass("Master passphrase: ")

    if args.mode == "encrypt":
        confirm = getpass.getpass("Confirm passphrase: ")

        if password != confirm:
            print("Passphrases do not match.")
            return 1

    # Create or load salt
    salt_file = vault / SALT_FILE

    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = os.urandom(16)
        salt_file.write_bytes(salt)

    # Generate encryption key
    key = derive_key(password, salt)
    cipher = Fernet(key)

    # Create recovery-key backup
    if args.mode == "encrypt":
        backup = vault / BACKUP_FILE
        backup.write_text(key.decode("ascii"), encoding="utf-8")

        try:
            os.chmod(backup, 0o600)
        except OSError:
            pass

    count = 0

    # Process files recursively
    for file in sorted(vault.rglob("*")):

        if not file.is_file():
            continue

        if file.name in {SALT_FILE, BACKUP_FILE}:
            continue

        # Encryption
        if args.mode == "encrypt":

            if file.suffix == ".enc":
                continue

            encrypted_file = file.with_name(
                file.name + ".enc"
            )

            encrypted_data = cipher.encrypt(
                file.read_bytes()
            )

            encrypted_file.write_bytes(encrypted_data)
            file.unlink()

            print(
                f"ENCRYPTED: {file.relative_to(vault)} "
                f"-> {encrypted_file.relative_to(vault)}"
            )

            count += 1

        # Decryption
        else:

            if file.suffix != ".enc":
                continue

            original_file = file.with_name(
                file.name[:-4]
            )

            try:
                decrypted_data = cipher.decrypt(
                    file.read_bytes()
                )

                original_file.write_bytes(decrypted_data)
                file.unlink()

                print(
                    f"DECRYPTED: {file.relative_to(vault)} "
                    f"-> {original_file.relative_to(vault)}"
                )

                count += 1

            except InvalidToken:
                print(
                    f"FAILED: Invalid password or corrupted file: "
                    f"{file.relative_to(vault)}"
                )

    print("\n=== VAULT SUMMARY ===")
    print("Mode:", args.mode)
    print("Directory:", vault)
    print("Files processed:", count)
    print("Status:", "SUCCESS" if count else "NO FILES PROCESSED")


if __name__ == "__main__":
    main()
```

## Usage

### Encrypt a Directory

```bash
python vault.py encrypt test_vault
```

Example:

```text
Master passphrase: ********
Confirm passphrase: ********
ENCRYPTED: notes.txt -> notes.txt.enc
ENCRYPTED: report.txt -> report.txt.enc
ENCRYPTED: data/sample.csv -> data/sample.csv.enc

=== VAULT SUMMARY ===
Mode: encrypt
Directory: /project/test_vault
Files processed: 3
Status: SUCCESS
```

### Decrypt a Directory

```bash
python vault.py decrypt test_vault
```

Example:

```text
Master passphrase: ********
DECRYPTED: notes.txt.enc -> notes.txt
DECRYPTED: report.txt.enc -> report.txt
DECRYPTED: data/sample.csv.enc -> data/sample.csv

=== VAULT SUMMARY ===
Mode: decrypt
Directory: /project/test_vault
Files processed: 3
Status: SUCCESS
```

## How It Works

1. The program scans the selected directory recursively.
2. A random salt is generated for a new vault.
3. PBKDF2-HMAC-SHA256 derives an encryption key from the master passphrase.
4. Fernet encrypts each file individually.
5. Encrypted files receive the `.enc` extension.
6. During decryption, Fernet verifies the encrypted data before restoring it.
7. The program displays the number of files processed.

## Key Management

The master passphrase is not stored by the program. A local
`.vault_salt` file is used for key derivation.

The program also creates `.vault_key_backup.txt` as a recovery backup.

**Do not upload `.vault_key_backup.txt` or any real passphrase to GitHub.**

## Submission Proof

The project submission contains:

- `vault.py` — Cryptographic Encryption Vault source code
- `execution_log.txt` — sample execution log
- `README.md` — project documentation
- Execution screenshots — encryption and decryption proof

## Security Notice

Use this project only with files and directories you own or are authorized
to protect. Keep backups of important data before testing encryption.

## Author

**Sai Nikitha**
