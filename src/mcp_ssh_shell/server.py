from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
import uvicorn

from .state import SSHSessionManager
from .auth import QueryKeyAuthMiddleware


manager = SSHSessionManager()
mcp = FastMCP("SSH Shell")


@mcp.tool()
async def ssh_connect(
    alias: str,
    host: str,
    username: str,
    port: int = 22,
    password: str | None = None,
    private_key_path: str | None = None,
    private_key_passphrase: str | None = None,
    known_hosts: str | None = None,
    connect_timeout: float = 15.0,
    term_type: str = "xterm-256color",
    request_pty: bool = False,
) -> dict[str, Any]:
    """Create a persistent SSH shell, store its connection, and activate it."""
    return await manager.connect(
        alias,
        host,
        username,
        port=port,
        password=password,
        private_key_path=private_key_path,
        private_key_passphrase=private_key_passphrase,
        known_hosts=known_hosts,
        connect_timeout=connect_timeout,
        term_type=term_type,
        request_pty=request_pty,
    )


@mcp.tool()
async def ssh_switch(alias: str) -> dict[str, Any]:
    """Switch all future shell commands to the selected SSH session."""
    return await manager.switch(alias)


@mcp.tool()
async def ssh_execute(
    command: str,
    timeout_seconds: float = 60.0,
    cwd: str | None = None,
) -> dict[str, Any]:
    """Run one command in the persistent active SSH shell."""
    return await manager.execute(command, timeout_seconds=timeout_seconds, cwd=cwd)


@mcp.tool()
async def ssh_set_cwd(path: str) -> dict[str, Any]:
    """Change and persist the active SSH session's working directory."""
    return await manager.set_cwd(path)


@mcp.tool()
async def ssh_status() -> dict[str, Any]:
    """Return the active session and all registered SSH sessions."""
    return await manager.status()


@mcp.tool()
async def ssh_disconnect(alias: str | None = None, forget: bool = False) -> dict[str, Any]:
    """Disconnect a session; optionally delete its stored connection."""
    return await manager.disconnect(alias, forget=forget)


def main() -> None:
    parser = argparse.ArgumentParser(description="MCP Streamable HTTP SSH shell server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log-level", default="INFO")
    default_database = os.environ.get(
        "MCP_SSH_DB",
        str(Path.home() / ".local" / "share" / "mcp-ssh-shell" / "connections.db"),
    )
    parser.add_argument("--db", default=default_database)
    parser.add_argument("--secret-key-file", default=None)
    parser.add_argument("--auth-key", default=os.environ.get("MCP_AUTH_KEY"))
    args = parser.parse_args()

    loopback_hosts = {"127.0.0.1", "::1", "localhost"}
    if not args.auth_key and args.host not in loopback_hosts:
        parser.error("non-loopback exposure requires --auth-key or MCP_AUTH_KEY")

    logging.basicConfig(level=args.log_level.upper())
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    manager.configure_storage(
        args.db,
        secret_key=os.environ.get("MCP_SSH_SECRET_KEY"),
        secret_key_path=args.secret_key_file,
    )
    try:
        app = mcp.streamable_http_app()
        if args.auth_key:
            app = QueryKeyAuthMiddleware(app, args.auth_key)
        config = uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            log_level=args.log_level.lower(),
        )

        async def serve() -> None:
            server = uvicorn.Server(config)
            try:
                await server.serve()
            finally:
                await manager.close_all()

        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    finally:
        asyncio.run(manager.close_all())
        manager.close_storage()
