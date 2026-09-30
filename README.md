# MCP SSH Shell Server

一个基于 MCP Streamable HTTP 的有状态 SSH 服务。每个连接别名维护一个持久远端 shell；
所有 `ssh_execute` 调用都发送到当前激活的连接，因此环境变量、终端状态和交互副作用会保留。
连接配置会保存到 SQLite；密码和私钥口令使用 Fernet 加密存储。

## 启动

```bash
uv sync
uv run mcp-ssh-shell --host 127.0.0.1 --port 8000
```

默认数据库是 `~/.local/share/mcp-ssh-shell/connections.db`，可用 `--db` 覆盖。
加密密钥默认保存在数据库同目录的 `.secret-key`；也可设置 `MCP_SSH_SECRET_KEY` 或指定
`--secret-key-file`。请同时保护数据库和密钥文件。

MCP endpoint:

```text
http://127.0.0.1:8000/mcp
```

### 访问控制

公网或非本机监听必须设置访问密钥：

```bash
uv run mcp-ssh-shell --host 0.0.0.0 --port 8000 --auth-key 'long-random-value'
```

客户端访问：

```text
http://127.0.0.1:8000/mcp?key=long-random-value
```

密钥也可通过 `MCP_AUTH_KEY` 环境变量提供。非回环地址缺少密钥时服务会拒绝启动。
由于 URL 查询参数可能出现在代理或访问日志中，请使用足够长的随机值，并优先通过 HTTPS 反向代理暴露。

## 工具

- `ssh_connect`: 建立、保存并激活一个 SSH 连接。
- `ssh_connect` 默认 `request_pty=false`，输出干净；需要交互终端时可设为 `true`。
- `ssh_switch`: 在已建立的连接之间切换；运行会话不存在时自动从 SQLite 重连。
- `ssh_execute`: 在当前连接的持久 shell 中执行命令。
- `ssh_set_cwd`: 显式切换当前工作路径。
- `ssh_status`: 查看当前连接和全部会话。
- `ssh_disconnect`: 断开指定或当前连接；`forget=true` 时同时删除数据库记录。

连接支持密码或私钥文件认证。生产环境建议保留 host key 校验；仅在隔离环境使用
`known_hosts="none"`。
