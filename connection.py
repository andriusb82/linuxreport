from __future__ import annotations

import socket
from typing import Tuple

import paramiko


class SSHConnectionError(Exception):
    pass


class SSHConnectionManager:
    def __init__(self, host: str, port: int, username: str, password: str, timeout: int = 10) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._timeout = timeout
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                timeout=self._timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            self._client = client
        except (paramiko.SSHException, socket.error) as exc:
            raise SSHConnectionError(f"SSH connection failed: {exc}") from exc

    def disconnect(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def execute(self, command: str) -> Tuple[str, str, int]:
        if self._client is None:
            raise SSHConnectionError("SSH client is not connected.")

        stdin, stdout, stderr = self._client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return out, err, exit_code