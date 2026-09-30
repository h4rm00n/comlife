from __future__ import annotations

import asyncio
import base64
import re
import secrets
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import asyncssh

from .storage import ConnectionStore


class SSHShellError(RuntimeError):
    """Raised for SSH session and command execution errors."""


@dataclass
class SessionState:
    alias: str
    host: str
    username: str
    connection: asyncssh.SSHClientConnection
    process: asyncssh.SSHClientProcess
    cwd: str
    busy: bool = False
    created_at: str = ""


class SSHSessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionState] = {}
        self._active_alias: str | None = None
        self._lock = asyncio.Lock()
        self._store: ConnectionStore | None = None

    def configure_storage(
        self,
        database_path: str,
        *,
        secret_key: str | bytes | None = None,
        secret_key_path: str | None = None,
    ) -> None:
        if self._sessions:
            raise SSHShellError("Cannot change storage while SSH sessions are active")
        if self._store is not None:
            self._store.close()
        self._store = ConnectionStore(
            database_path,
            secret_key=secret_key,
            secret_key_path=secret_key_path,
        )

    async def connect(
        self,
        alias: str,
        host: str,
        username: str,
        *,
        port: int = 22,
        password: str | None = None,
        private_key_path: str | None = None,
        private_key_passphrase: str | None = None,
        known_hosts: str | None = None,
        connect_timeout: float = 15.0,
        term_type: str = "xterm-256color",
        request_pty: bool = False,
    ) -> dict[str, Any]:
        if not alias or not host or not username:
            raise SSHShellError("alias, host, and username are required")
        if not password and not private_key_path:
            raise SSHShellError("password or private_key_path is required")
        if self._store is None:
            raise SSHShellError("SQLite connection storage is not configured")

        async with self._lock:
            if alias in self._sessions:
                raise SSHShellError(f"SSH session already exists: {alias}")
            connection, process, initial_cwd = await self._open_shell(
                host=host,
                username=username,
                port=port,
                password=password,
                private_key_path=private_key_path,
                private_key_passphrase=private_key_passphrase,
                known_hosts=known_hosts,
                connect_timeout=connect_timeout,
                term_type=term_type,
                request_pty=request_pty,
            )
            try:
                self._store.upsert(
                    alias,
                    host,
                    username,
                    port=port,
                    term_type=term_type,
                    known_hosts=known_hosts,
                    private_key_path=private_key_path,
                    password=password,
                    private_key_passphrase=private_key_passphrase,
                    connect_timeout=connect_timeout,
                )
            except Exception:
                connection.close()
                await connection.wait_closed()
                raise

            self._sessions[alias] = SessionState(
                alias=alias,
                host=host,
                username=username,
                connection=connection,
                process=process,
                cwd=initial_cwd,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._active_alias = alias
            return self._status_locked()

    async def switch(self, alias: str) -> dict[str, Any]:
        async with self._lock:
            if alias in self._sessions:
                self._active_alias = alias
                return self._status_locked()
            return await self._reconnect_locked(alias)

    async def _reconnect_locked(self, alias: str) -> dict[str, Any]:
        if self._store is None:
            raise SSHShellError("SQLite connection storage is not configured")
        stored = self._store.get(alias)
        if stored is None:
            raise SSHShellError(f"Unknown SSH session: {alias}")

        credentials = self._store.credentials(alias)
        if not credentials.password and not stored.private_key_path:
            raise SSHShellError(
                f"No reusable credential is stored for {alias}; call ssh_connect first"
            )
        connection, process, initial_cwd = await self._open_shell(
            host=stored.host,
            username=stored.username,
            port=stored.port,
            password=credentials.password,
            private_key_path=stored.private_key_path,
            private_key_passphrase=credentials.private_key_passphrase,
            known_hosts=stored.known_hosts,
            connect_timeout=stored.connect_timeout,
            term_type=stored.term_type,
            request_pty=False,
        )
        self._sessions[alias] = SessionState(
            alias=alias,
            host=stored.host,
            username=stored.username,
            connection=connection,
            process=process,
            cwd=initial_cwd,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._active_alias = alias
        return self._status_locked()

    async def _open_shell(
        self,
        *,
        host: str,
        username: str,
        port: int,
        password: str | None,
        private_key_path: str | None,
        private_key_passphrase: str | None,
        known_hosts: str | None,
        connect_timeout: float,
        term_type: str,
        request_pty: bool,
    ) -> tuple[asyncssh.SSHClientConnection, asyncssh.SSHClientProcess, str]:
        connection: asyncssh.SSHClientConnection | None = None
        try:
            connection = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                client_keys=[private_key_path] if private_key_path else None,
                passphrase=private_key_passphrase,
                known_hosts=known_hosts,
                login_timeout=connect_timeout,
            )
            process = await connection.create_process(
                term_type=term_type,
                request_pty=request_pty,
            )
            await asyncio.sleep(0.05)
            await self._drain_output(process)
            initial_cwd = await self._request_cwd(process)
            return connection, process, initial_cwd
        except Exception as exc:
            if connection is not None:
                connection.close()
                await connection.wait_closed()
            if isinstance(exc, asyncssh.Error):
                raise SSHShellError(f"SSH connection failed: {exc}") from exc
            raise SSHShellError(f"SSH session setup failed: {exc}") from exc

    async def set_cwd(self, path: str) -> dict[str, Any]:
        if not path:
            raise SSHShellError("path is required")
        return await self.execute(f"cd {shlex.quote(path)}")

    async def execute(
        self,
        command: str,
        *,
        timeout_seconds: float = 60.0,
        cwd: str | None = None,
    ) -> dict[str, Any]:
        if not command.strip():
            raise SSHShellError("command must not be empty")

        async with self._lock:
            session = self._active_session()
            if session.busy:
                raise SSHShellError(f"Active shell is busy: {session.alias}")

            session.busy = True
            token = secrets.token_urlsafe(12)
            marker = f"__MCP_SSH_END_{token}__"
            target_cwd = cwd or session.cwd
            encoded_command = base64.b64encode(command.encode()).decode()
            marker_code = (
                f'__MCP_RC=$?; __MCP_PWD=$(pwd); '
                f'printf "\\n{marker}:%s:%s\\n" "$__MCP_RC" "$__MCP_PWD"; '
                f'unset __MCP_RC __MCP_PWD'
            )
            wrapped = (
                f'cd {shlex.quote(target_cwd)}; '
                f'__MCP_CMD=$(printf %s {shlex.quote(encoded_command)} | base64 -d); '
                f'eval "$__MCP_CMD"; '
                f'{marker_code}; unset __MCP_CMD\n'
            )

            try:
                session.process.stdin.write(wrapped)
                await session.process.stdin.drain()
                raw_output = await self._read_until_marker(
                    session.process,
                    marker,
                    timeout_seconds=timeout_seconds,
                )
                output, exit_code, resulting_cwd = self._parse_result(
                    raw_output, marker
                )
                session.cwd = resulting_cwd
                return {
                    "alias": session.alias,
                    "cwd": session.cwd,
                    "exit_code": exit_code,
                    "output": output,
                    "timed_out": False,
                }
            except asyncio.TimeoutError as exc:
                session.process.stdin.write("\x03")
                await session.process.stdin.drain()
                try:
                    await self._read_until_marker(
                        session.process,
                        marker,
                        timeout_seconds=2.0,
                    )
                except (asyncio.TimeoutError, SSHShellError):
                    pass
                raise SSHShellError(
                    f"Command timed out after {timeout_seconds}s; sent SIGINT"
                ) from exc
            except asyncssh.Error as exc:
                raise SSHShellError(f"SSH command failed: {exc}") from exc
            finally:
                session.busy = False

    async def disconnect(
        self,
        alias: str | None = None,
        *,
        forget: bool = False,
    ) -> dict[str, Any]:
        async with self._lock:
            target = alias or self._active_alias
            if not target:
                raise SSHShellError("No active SSH session")
            if forget:
                if self._store is None:
                    raise SSHShellError("SQLite connection storage is not configured")
                self._store.delete(target)
            if target not in self._sessions:
                if forget:
                    return self._status_locked()
                raise SSHShellError(f"Unknown SSH session: {target}")

            session = self._sessions.pop(target)
            session.connection.close()
            await session.connection.wait_closed()
            if self._active_alias == target:
                self._active_alias = next(iter(self._sessions), None)
            return self._status_locked()

    async def status(self) -> dict[str, Any]:
        async with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict[str, Any]:
        if self._store is None:
            raise SSHShellError("SQLite connection storage is not configured")
        sessions = []
        for alias, session in self._sessions.items():
            sessions.append(
                {
                    "alias": alias,
                    "host": session.host,
                    "username": session.username,
                    "cwd": session.cwd,
                    "busy": session.busy,
                    "created_at": session.created_at,
                    "active": alias == self._active_alias,
                }
            )
        stored_connections = [
            {
                "alias": stored.alias,
                "host": stored.host,
                "username": stored.username,
                "port": stored.port,
                "has_password": stored.has_password,
                "has_private_key_passphrase": stored.has_private_key_passphrase,
                "active_session": stored.alias in self._sessions,
                "created_at": stored.created_at,
                "updated_at": stored.updated_at,
            }
            for stored in self._store.list()
        ]
        return {
            "active_alias": self._active_alias,
            "sessions": sessions,
            "stored_connections": stored_connections,
        }

    async def close_all(self) -> None:
        while self._sessions:
            await self.disconnect(next(iter(self._sessions)))

    def close_storage(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None

    def _active_session(self) -> SessionState:
        if self._active_alias is None:
            raise SSHShellError("No active SSH session; call ssh_connect first")
        return self._sessions[self._active_alias]

    @staticmethod
    async def _drain_output(process: asyncssh.SSHClientProcess) -> str:
        try:
            data = await asyncio.wait_for(process.stdout.read(65536), timeout=0.2)
            return data.decode(errors="replace") if isinstance(data, bytes) else data
        except asyncio.TimeoutError:
            return ""

    @staticmethod
    async def _request_cwd(process: asyncssh.SSHClientProcess) -> str:
        marker = secrets.token_urlsafe(12)
        command = (
            f'printf "\\n__MCP_CWD_{marker}__:0:%s\\n" "$PWD"\n'
        )
        process.stdin.write(command)
        await process.stdin.drain()
        output = await SSHSessionManager._read_until_marker(
            process, f"__MCP_CWD_{marker}__", timeout_seconds=15
        )
        return SSHSessionManager._parse_result(output, f"__MCP_CWD_{marker}__")[2]

    @staticmethod
    async def _read_until_marker(
        process: asyncssh.SSHClientProcess,
        marker: str,
        *,
        timeout_seconds: float,
    ) -> str:
        chunks: list[str] = []

        async def reader() -> None:
            while True:
                data = await process.stdout.read(8192)
                if data is None or data == "":
                    break
                chunks.append(data.decode(errors="replace") if isinstance(data, bytes) else data)
                if re.search(rf"^{re.escape(marker)}:", "".join(chunks), re.MULTILINE):
                    break

        task = asyncio.create_task(reader())
        try:
            await asyncio.wait_for(task, timeout=timeout_seconds)
        except Exception:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
            raise
        return "".join(chunks)

    @staticmethod
    def _parse_result(output: str, marker: str) -> tuple[str, int, str]:
        matches = list(re.finditer(rf"^({re.escape(marker)}):(-?\d+):(.*)$", output, re.MULTILINE))
        if not matches:
            raise SSHShellError("SSH shell did not return its synchronization marker")
        last = matches[-1]
        return output[: last.start()].strip("\r\n"), int(last.group(2)), last.group(3).strip()
