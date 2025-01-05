from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from pathlib import Path
import logging
import sqlite3
import hashlib
import os
import time
import threading
from typing import List, Tuple
from dataclasses import dataclass
import yaml
from DatabaseManager import DatabaseManager
from FileMetaData import FileMetadata
from IntegrityMonitor import IntegrityMonitor

class CryptoLock:
    """Demonstration of file encryption and logging."""

    def __init__(self, base_dir: str = "crypto_lock"):
        """
        Initialize the CryptoLock environment.
        :param base_dir: Base directory for the demo files and configurations.
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.db_manager = DatabaseManager(self.base_dir / "operations.db")
        self.integrity_monitor = IntegrityMonitor()
        self.keys_dir = self.base_dir / "keys"
        self.files_dir = self.base_dir / "files"
        self.encrypted_dir = self.base_dir / "encrypted"
        self.logs_dir = self.base_dir / "logs"

        for directory in [self.keys_dir, self.files_dir, self.encrypted_dir, self.logs_dir]:
            directory.mkdir(exist_ok=True)

        self._setup_logging()
        self.symmetric_key = None
        self.key_rotation_interval = 3600  # Rotate key every hour
        self.key_rotation_thread = threading.Thread(target=self._rotate_keys_periodically, daemon=True)
        self.key_rotation_thread.start()

    def _setup_logging(self):
        """
        Set up logging for the application.
        """
        self.logger = logging.getLogger("CryptoLock")
        self.logger.setLevel(logging.DEBUG)

        # File handler for logs
        file_handler = logging.FileHandler(self.logs_dir / "crypto_lock.log")
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

        # Console handler for real-time updates
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        self.logger.addHandler(console_handler)

    def generate_symmetric_key(self):
        """
        Generate and save a symmetric encryption key.
        """
        try:
            self.symmetric_key = Fernet.generate_key()
            key_path = self.keys_dir / "symmetric.key"
            with open(key_path, 'wb') as f:
                f.write(self.symmetric_key)
            self.logger.info("Generated symmetric key.")
        except Exception as e:
            self.logger.error(f"Failed to generate symmetric key: {e}")

    def _rotate_keys_periodically(self):
        """
        Rotate the symmetric key periodically based on the specified interval.
        """
        while True:
            time.sleep(self.key_rotation_interval)
            self.logger.info("Rotating symmetric key...")
            self.generate_symmetric_key()

    def create_demo_files(self, count: int = 5):
        """
        Create sample files with placeholder content.

        :param count: Number of demo files to create.
        Each file simulates a specific input type for encryption testing and includes
        placeholder content. File types include:
        - .txt: Basic text files
        - .json: JSON-formatted files
        - .yaml: YAML configuration files
        """
        try:
            file_types = [".txt", ".json", ".yaml"]
            for i in range(count):
                ext = file_types[i % len(file_types)]
                file_path = self.files_dir / f"file_{i}{ext}"
                with open(file_path, 'w') as f:
                    f.write(f"This is demo file {i}{ext}")
                self.logger.info(f"Created file: {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to create demo files: {e}")

    def encrypt_files(self):
        """
        Encrypt files in the files directory.
        """
        if not self.symmetric_key:
            self.generate_symmetric_key()
        cipher = Fernet(self.symmetric_key)

        for file_path in self.files_dir.iterdir():
            if file_path.suffix in [".txt", ".json", ".yaml"]:
                try:
                    # Read the original file data
                    with open(file_path, 'rb') as f:
                        data = f.read()

                    # Encrypt the file data
                    encrypted_data = cipher.encrypt(data)

                    # Save the encrypted file
                    encrypted_path = self.encrypted_dir / f"{file_path.stem}_encrypted{file_path.suffix}"
                    with open(encrypted_path, 'wb') as f:
                        f.write(encrypted_data)

                    # Log metadata about the encryption process
                    metadata = FileMetadata(
                        original_path=file_path,
                        original_hash=self.integrity_monitor.calculate_hash(file_path),
                        encrypted_path=encrypted_path,
                        encrypted_hash=self.integrity_monitor.calculate_hash(encrypted_path),
                    )

                    self.db_manager.log_operation(metadata, "encryption", "success")
                    self.logger.info(f"Encrypted file: {file_path} -> {encrypted_path}")
                except Exception as e:
                    self.logger.error(f"Failed to encrypt {file_path}: {e}")

    def run_demo(self):
        """
        Run the full demonstration, including file creation and encryption.
        """
        self.logger.info("Starting CryptoLock...")
        self.create_demo_files()
        self.encrypt_files()
        self.logger.info("Demo completed.")


if __name__ == "__main__":
    demo = CryptoLock()
    demo.run_demo()
