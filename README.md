# CryptoLock: Secure File Encryption and Logging

## Overview
**CryptoLock** is a Python-based demonstration project that showcases **file encryption, integrity verification**, and **secure logging** using modern cryptographic and data management practices. This project highlights secure file handling through the use of **Fernet encryption**, **SQLite** for metadata logging, and **SHA-256 hash-based integrity checks**.

The name **CryptoLock** is inspired by the infamous **CryptoLocker ransomware attack**, which operated from early September 2013 to late May 2014. CryptoLocker encrypted files on victim computers and held them hostage for a ransom, demonstrating the destructive power of improper encryption usage. In stark contrast, **CryptoLock** focuses on demonstrating ethical and secure encryption practices to protect and manage sensitive data responsibly.

### Key Features
- **Symmetric Key Encryption**: Automatically generates and rotates **Fernet keys** for secure file encryption.
- **File Integrity Verification**: Utilizes **SHA-256** hashing to ensure file integrity before and after encryption.
- **Database Logging**: Logs all operations, including encryption details and metadata, into an **SQLite** database for traceability.
- **Thread-Safe Key Rotation**: Periodically rotates symmetric keys in a **thread-safe manner**.
- **Scalable Demo File Handling**: Generates demo files in multiple formats (**.txt**, **.json**, **.yaml**) for testing and showcases encryption and logging workflows.

## Setup
### Prerequisites
- Python 3.8+
- Required libraries (install via `pip`):
  ```bash
  pip install cryptography pyyaml
  ```

### Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/cryptolock.git
   cd cryptolock
   ```
2. Run the script:
   ```bash
   python cryptolock.py
   ```

## Usage
### Main Functionalities
#### 1. **Generate Symmetric Key**
   The application automatically generates a **Fernet symmetric key** for file encryption and securely saves it in the `keys` directory.

#### 2. **Create Demo Files**
   Generates a set of **sample files** in the `files` directory with placeholder content for testing purposes.

#### 3. **Encrypt Files**
   Encrypts files in the `files` directory, saving the encrypted versions in the `encrypted` directory and verifying their integrity using **SHA-256 hashes**.

#### 4. **Log Metadata**
   Records metadata for each operation (e.g., file paths, hashes, operation type, status) into an **SQLite database** stored in `operations.db`.

#### 5. **Periodic Key Rotation**
   Runs a background thread to rotate the symmetric key every hour, ensuring **forward security**.

### Example Workflow
1. Start the demo:
   ```bash
   python cryptolock.py
   ```
2. View the logs:
   - Check the `logs/crypto_lock.log` file for real-time updates.
3. Query database logs:
   ```bash
   sqlite3 crypto_lock/operations.db "SELECT * FROM file_operations;"
   ```

## Directory Structure
```
crypto_lock/
├── keys/          # Stores the symmetric key file
├── files/         # Contains generated demo files
├── encrypted/     # Stores encrypted versions of the demo files
├── logs/          # Application logs
├── operations.db  # SQLite database for logging metadata
└── crypto_lock.py  # Main application script
```

## Future Improvements
- **Enhanced Log Querying**: Add support for dynamic filtering of logs (e.g., by operation type, status, or date range).
- **Key Storage Security**: Encrypt the symmetric key file using an RSA public key for added security.
- **Extended Scalability**: Implement multi-threading or asynchronous processing for large-scale file operations.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your improvements or fixes.


