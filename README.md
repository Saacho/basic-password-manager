# Password Vault

A (mostly) secure, command-line password manager written in Java. Password Vault allows users to store, retrieve, and manage credentials with strong AES encryption, PBKDF2 key derivation, and optional random password/passphrase generation.

**All of the code necessary to run the project is contained in one file for your convenience :)

## Features

- **AES-128/CBC Encryption** — Protects all stored credentials using industry-standard symmetric encryption with randomized IVs.
- **PBKDF2 Key Derivation** — Derives encryption keys from a master password with salt and 600,000 iterations to resist brute-force attacks.
- **Secure Data Persistence** — Stores encrypted passwords, admin credentials, salts, and logs in local files, maintaining access across sessions.
- **Admin Privilege System** — Restricts sensitive operations like viewing all credentials or audit logs to an administrator account.
- **Interactive CLI** — Add, remove, search, and export passwords with a menu-driven interface.
- **Random Password & Passphrase Generation** — Generate strong passwords or human-readable passphrases (with optional acronyms) from customizable character sets or word lists.
- **Undo Support** — Safely revert the last add/remove action via a stack-based action history.
- **Audit Logging** — Tracks administrative actions with timestamps for accountability and troubleshooting.

## File Structure

| File                     | Purpose                              |
|--------------------------|--------------------------------------|
| `PasswordVault.java`     | Main application source code         |
| `user_passwords.csv`     | Encrypted username-password storage  |
| `admin_password.txt`     | Stores admin password (plaintext, restricted) |
| `salt.txt`               | Stores the randomly generated salt   |
| `key.dat`                | Stores the AES key                   |
| `vault_log.txt`          | Audit logs with timestamps           |
| `words_alpha.txt` (optional) | Word list for passphrase generation |

## Getting Started

### Prerequisites
- Java 11 or newer
- A terminal or command prompt

### Running the Application
1. Compile the source code:
   ```bash
   javac PasswordVault.java
   ```
2. Run the program:
   ```bash
   java PasswordVault
   ```
3. On first launch:
   - You will be prompted to enter a master password.
   - A new AES key and salt will be generated if none exist.
   - You may export any existing passwords before reinitializing.
4. Use the interactive menu to add, remove, search, or export credentials.

---

**Author:** Saachi Kandula
**Date:** 2025


