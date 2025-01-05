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
from FileMetaData import FileMetadata

class DatabaseManager:
    """Manage SQLite database for logging file operations and events."""

    def __init__(self, db_path: Path):
        """
        Initialize the DatabaseManager.
        :param db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        """
        Create the necessary tables and indices in the database if they do not exist.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY,
                    original_path TEXT,
                    encrypted_path TEXT,
                    original_hash TEXT,
                    encrypted_hash TEXT,
                    timestamp TEXT,
                    operation_type TEXT,
                    status TEXT
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON file_operations (timestamp)
            ''')

    def log_operation(self, metadata: FileMetadata, operation_type: str, status: str):
        """
        Log an operation in the database.
        :param metadata: Metadata about the file being processed.
        :param operation_type: Type of operation performed (e.g., encryption).
        :param status: Status of the operation (e.g., success, failure).
        """
        # Expected operations: "encryption", "decryption", "hash verification"
        # Expected statuses: "success", "failure"
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO file_operations 
                    (original_path, encrypted_path, original_hash, encrypted_hash, 
                    timestamp, operation_type, status)
                    VALUES (?, ?, ?, ?, datetime('now'), ?, ?)
                ''', (
                    str(metadata.original_path),
                    str(metadata.encrypted_path),
                    metadata.original_hash,
                    metadata.encrypted_hash,
                    operation_type,
                    status
                ))
        except Exception as e:
            logging.error(f"Database logging error: {e}")

    def query_logs(self, operation_type: str = None):
        """
        Query logs based on operation type.
        :param operation_type: Type of operation to filter logs (optional).
        :return: List of log entries matching the criteria.
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                query = 'SELECT * FROM file_operations'
                if operation_type:
                    query += f" WHERE operation_type = '{operation_type}'"
                return conn.execute(query).fetchall()
        except Exception as e:
            logging.error(f"Log query error: {e}")
            return []