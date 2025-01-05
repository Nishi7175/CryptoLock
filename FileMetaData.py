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

@dataclass
class FileMetadata:
    """Store metadata about processed files."""
    original_path: Path  # Path of the original file before encryption
    original_hash: str  # Hash of the original file for integrity verification
    encrypted_path: Path = None  # Path of the encrypted file
    encrypted_hash: str = None  # Hash of the encrypted file
    encryption_time: float = None  # Time taken to encrypt the file
    size: int = 0  # Size of the original file in bytes
    processed: bool = False  # Flag indicating if the file has been processed
