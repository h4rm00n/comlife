from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class SSHStorageError(RuntimeError):
    """Raised for connection database and credential encryption errors."""


@dataclass(frozen=True)
class StoredConnection:
    alias: str
    host: str
    username: str
    port: int
    term_type: str
    known_hosts: str | None
    private_key_path: str | None
    connect_timeout: float
    has_password: bool
    has_private_key_passphrase: bool
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class StoredCredentials:
    password: str | None
    private_key_passphrase: str | None


def prepare_secret_key(
    *,
    secret_key: str | bytes | None,
    secret_key_path: str | Path | None,
    database_path: str | Path,
) -> bytes:
    if secret_key is not None:
        raw_key = secret_key.encode() if isinstance(secret_key, str) else secret_key
        try:
            Fernet(raw_key)
        except (ValueError, TypeError) as exc:
            raise SSHStorageError("MCP_SSH_SECRET_KEY is not a valid Fernet key") from exc
        return raw_key

    key_path = Path(secret_key_path or Path(database_path).parent / ".secret-key")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        try:
            raw_key = key_path.read_bytes().strip()
            Fernet(raw_key)
        except (OSError, ValueError) as exc:
            raise SSHStorageError(f"Invalid secret key file: {key_path}") from exc
        return raw_key

    raw_key = Fernet.generate_key()
    try:
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(raw_key)
    except FileExistsError:
        raw_key = key_path.read_bytes().strip()
        try:
            Fernet(raw_key)
        except (OSError, ValueError) as exc:
            raise SSHStorageError(f"Invalid secret key file: {key_path}") from exc
    except OSError as exc:
        raise SSHStorageError(f"Could not create secret key file: {key_path}") from exc
    return raw_key


class ConnectionStore:
    def __init__(
        self,
        database_path: str | Path,
        *,
        secret_key: str | bytes | None = None,
        secret_key_path: str | Path | None = None,
    ) -> None:
        self._path = Path(database_path).expanduser()
        self._fernet = Fernet(
            prepare_secret_key(
                secret_key=secret_key,
                secret_key_path=secret_key_path,
                database_path=self._path,
            )
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(self._path)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._initialize()
        except sqlite3.Error as exc:
            raise SSHStorageError(f"Could not open connection database: {exc}") from exc

    def close(self) -> None:
        self._connection.close()

    def upsert(
        self,
        alias: str,
        host: str,
        username: str,
        *,
        port: int,
        term_type: str,
        known_hosts: str | None,
        private_key_path: str | None,
        password: str | None,
        private_key_passphrase: str | None,
        connect_timeout: float,
    ) -> StoredConnection:
        now = datetime.now(timezone.utc).isoformat()
        encrypted_password = self._encrypt(password) if password is not None else None
        encrypted_passphrase = (
            self._encrypt(private_key_passphrase)
            if private_key_passphrase is not None
            else None
        )
        try:
            self._connection.execute(
                """
                INSERT INTO ssh_connections (
                    alias, host, username, port, term_type, known_hosts,
                    private_key_path, password_encrypted,
                    private_key_passphrase_encrypted, connect_timeout,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(alias) DO UPDATE SET
                    host = excluded.host,
                    username = excluded.username,
                    port = excluded.port,
                    term_type = excluded.term_type,
                    known_hosts = excluded.known_hosts,
                    private_key_path = COALESCE(
                        excluded.private_key_path, ssh_connections.private_key_path
                    ),
                    password_encrypted = COALESCE(
                        excluded.password_encrypted,
                        ssh_connections.password_encrypted
                    ),
                    private_key_passphrase_encrypted = COALESCE(
                        excluded.private_key_passphrase_encrypted,
                        ssh_connections.private_key_passphrase_encrypted
                    ),
                    connect_timeout = excluded.connect_timeout,
                    updated_at = excluded.updated_at
                """,
                (
                    alias,
                    host,
                    username,
                    port,
                    term_type,
                    known_hosts,
                    private_key_path,
                    encrypted_password,
                    encrypted_passphrase,
                    connect_timeout,
                    now,
                    now,
                ),
            )
            self._connection.commit()
        except sqlite3.Error as exc:
            raise SSHStorageError(f"Could not save SSH connection: {exc}") from exc
        return self.get(alias)

    def get(self, alias: str) -> StoredConnection | None:
        row = self._select_by_alias(alias)
        return self._row_to_connection(row) if row is not None else None

    def list(self) -> list[StoredConnection]:
        try:
            rows = self._connection.execute(
                "SELECT * FROM ssh_connections ORDER BY alias"
            ).fetchall()
        except sqlite3.Error as exc:
            raise SSHStorageError(f"Could not list SSH connections: {exc}") from exc
        return [self._row_to_connection(row) for row in rows]

    def credentials(self, alias: str) -> StoredCredentials:
        row = self._select_by_alias(alias)
        if row is None:
            raise SSHStorageError(f"SSH connection is not stored: {alias}")
        try:
            password = (
                self._decrypt(row["password_encrypted"])
                if row["password_encrypted"] is not None
                else None
            )
            passphrase = (
                self._decrypt(row["private_key_passphrase_encrypted"])
                if row["private_key_passphrase_encrypted"] is not None
                else None
            )
        except InvalidToken as exc:
            raise SSHStorageError(
                f"Stored credentials for {alias} cannot be decrypted with this key"
            ) from exc
        return StoredCredentials(password=password, private_key_passphrase=passphrase)

    def delete(self, alias: str) -> bool:
        try:
            cursor = self._connection.execute(
                "DELETE FROM ssh_connections WHERE alias = ?", (alias,)
            )
            self._connection.commit()
        except sqlite3.Error as exc:
            raise SSHStorageError(f"Could not delete SSH connection: {exc}") from exc
        return cursor.rowcount > 0

    def _initialize(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_connections (
                alias TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                username TEXT NOT NULL,
                port INTEGER NOT NULL,
                term_type TEXT NOT NULL,
                known_hosts TEXT,
                private_key_path TEXT,
                password_encrypted TEXT,
                private_key_passphrase_encrypted TEXT,
                connect_timeout REAL NOT NULL DEFAULT 15.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._connection.commit()

    def _select_by_alias(self, alias: str) -> sqlite3.Row | None:
        try:
            return self._connection.execute(
                "SELECT * FROM ssh_connections WHERE alias = ?", (alias,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise SSHStorageError(f"Could not read SSH connection: {exc}") from exc

    def _encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        return self._fernet.decrypt(value.encode()).decode()

    @staticmethod
    def _row_to_connection(row: sqlite3.Row) -> StoredConnection:
        return StoredConnection(
            alias=row["alias"],
            host=row["host"],
            username=row["username"],
            port=row["port"],
            term_type=row["term_type"],
            known_hosts=row["known_hosts"],
            private_key_path=row["private_key_path"],
            connect_timeout=row["connect_timeout"],
            has_password=row["password_encrypted"] is not None,
            has_private_key_passphrase=row["private_key_passphrase_encrypted"] is not None,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
