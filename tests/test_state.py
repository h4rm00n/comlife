from __future__ import annotations

import asyncio
import base64
import re
import sqlite3

import pytest
from cryptography.fernet import Fernet

from mcp_ssh_shell.state import SSHSessionManager, SSHShellError


class FakeStdin:
    def __init__(self, shell: "FakeShell") -> None:
        self.shell = shell

    def write(self, data: str) -> None:
        self.shell.write(data)

    async def drain(self) -> None:
        return None


class FakeStdout:
    def __init__(self, shell: "FakeShell") -> None:
        self.shell = shell

    async def read(self, _size: int) -> str | None:
        if not self.shell.output:
            return None
        return self.shell.output.pop(0)


class FakeShell:
    def __init__(self) -> None:
        self.output: list[str] = []
        self.pwd = "/home/deploy"
        self.stdin = FakeStdin(self)
        self.stdout = FakeStdout(self)

    def write(self, data: str) -> None:
        cwd_marker = re.search(r"__MCP_CWD_([A-Za-z0-9_-]{16})__", data)
        if cwd_marker:
            token = cwd_marker.group(1)
            self.output.append(f"__MCP_CWD_{token}__:0:{self.pwd}\n")
            return
        marker = re.search(r"__MCP_SSH_END_([A-Za-z0-9_-]{16})__", data)
        if not marker:
            return
        token = marker.group(1)
        encoded = re.search(r"printf %s '?([A-Za-z0-9+/=]+)'?", data)
        if encoded:
            command = base64.b64decode(encoded.group(1)).decode()
            if command.startswith("cd /tmp"):
                self.pwd = "/tmp"
        self.output.append(f"output\n__MCP_SSH_END_{token}__:0:{self.pwd}\n")


class FakeConnection:
    def __init__(self, process: FakeShell) -> None:
        self.process = process

    async def create_process(self, term_type: str, request_pty: bool = False) -> FakeShell:
        return self.process

    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


async def test_requires_credentials() -> None:
    manager = SSHSessionManager()
    with pytest.raises(SSHShellError):
        await manager.connect("missing", "localhost", "root")


async def test_persistent_state_and_switch_routing(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import mcp_ssh_shell.state as state_module

    processes = {"a": FakeShell(), "b": FakeShell()}
    passwords: dict[str, str] = {}

    async def fake_connect(*args, **kwargs):
        passwords[kwargs["username"]] = kwargs["password"]
        return FakeConnection(processes[kwargs["username"]])

    monkeypatch.setattr(state_module.asyncssh, "connect", fake_connect)
    manager = SSHSessionManager()
    manager.configure_storage(
        tmp_path / "connections.db",
        secret_key=Fernet.generate_key(),
    )
    await manager.connect("a", "host-a", "a", password="x")
    await manager.connect("b", "host-b", "b", password="x")

    await manager.switch("a")
    result = await manager.execute("cd /tmp")
    assert result["alias"] == "a"
    assert result["cwd"] == "/tmp"
    assert processes["a"].pwd == "/tmp"
    assert processes["b"].pwd == "/home/deploy"

    await manager.switch("b")
    result = await manager.execute("pwd")
    assert result["alias"] == "b"
    assert result["cwd"] == "/home/deploy"

    status = await manager.status()
    assert {item["alias"] for item in status["stored_connections"]} == {"a", "b"}
    assert all(item["has_password"] for item in status["stored_connections"])

    with sqlite3.connect(tmp_path / "connections.db") as database:
        stored_password = database.execute(
            "SELECT password_encrypted FROM ssh_connections WHERE alias = 'a'"
        ).fetchone()[0]
    assert stored_password != "x"

    await manager.close_all()
    manager.close_storage()


async def test_switch_reconnects_saved_connection_after_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    import mcp_ssh_shell.state as state_module

    processes = {"a": FakeShell()}
    passwords: dict[str, str] = {}

    async def fake_connect(*args, **kwargs):
        passwords[kwargs["username"]] = kwargs["password"]
        return FakeConnection(processes[kwargs["username"]])

    monkeypatch.setattr(state_module.asyncssh, "connect", fake_connect)
    database = tmp_path / "connections.db"
    secret_key = Fernet.generate_key()
    manager = SSHSessionManager()
    manager.configure_storage(database, secret_key=secret_key)
    await manager.connect("a", "host-a", "a", password="secret-password")
    await manager.disconnect("a")
    status = await manager.status()
    saved = status["stored_connections"][0]
    assert status["active_alias"] is None
    assert status["sessions"] == []
    assert saved["alias"] == "a"
    assert saved["has_password"] is True
    assert saved["active_session"] is False
    manager.close_storage()

    restarted = SSHSessionManager()
    restarted.configure_storage(database, secret_key=secret_key)
    status = await restarted.switch("a")
    assert status["active_alias"] == "a"
    assert passwords["a"] == "secret-password"
    restarted.close_storage()
