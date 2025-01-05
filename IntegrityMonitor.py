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

class IntegrityMonitor:
    """
    Handles file integrity checks.

    This class provides utility methods for calculating file hashes and verifying
    file integrity. Use cases include:
    - Verifying file integrity after encryption to ensure data consistency.
    - Detecting unintended modifications by comparing hashes.
    - Supporting logging and database entries with accurate file integrity data.
    """

    @staticmethod
    def calculate_hash(file_path: Path) -> str:
        """
        Calculate the SHA-256 hash of a file.
        :param file_path: Path to the file.
        :return: Hexadecimal hash string.
        """
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Hash calculation failed for {file_path}: {e}")
            return ""

    @staticmethod
    def verify_integrity(file_path: Path, expected_hash: str) -> bool:
        """
        Verify the integrity of a file by comparing its hash with the expected hash.
        :param file_path: Path to the file.
        :param expected_hash: Expected SHA-256 hash of the file.
        :return: True if hashes match, False otherwise.
        """
        return IntegrityMonitor.calculate_hash(file_path) == expected_hash