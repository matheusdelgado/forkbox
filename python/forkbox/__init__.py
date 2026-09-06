"""
Forkbox: Deterministic, Ultra-Low Latency Sandboxing Engine for Autonomous AI Agents.
"""

import json
import socket
from typing import Optional

__version__ = "0.1.0"
SOCKET_PATH = "/tmp/forkbox.sock"


class SandboxResult:
    def __init__(self, data: dict):
        self.exit_code: int = data.get("exit_code", -1)
        self.stdout: str = data.get("stdout", "")
        self.stderr: str = data.get("stderr", "")
        self.timed_out: bool = data.get("timed_out", False)
        self.duration_us: int = data.get("duration_us", 0)
        self.duration_ms: float = self.duration_us / 1000.0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def __repr__(self) -> str:
        return (
            f"<SandboxResult code={self.exit_code} "
            f"time={self.duration_ms:.2f}ms "
            f"timed_out={self.timed_out}>"
        )


class Forkbox:
    @staticmethod
    def run(
        cmd: str,
        timeout_ms: int = 3000,
        allow_network: bool = False,
        socket_path: str = SOCKET_PATH,
    ) -> SandboxResult:
        """Executes a command inside an ephemeral, hardened Forkbox sandbox.

        Args:
            cmd: Command string to execute inside the sandbox.
            timeout_ms: Maximum execution time before SIGKILL (anti-DoS).
            allow_network: If False (default), executes with zero network access (CLONE_NEWNET).
            socket_path: Path to the Forkbox daemon UNIX domain socket.
        """
        payload = (
            json.dumps(
                {
                    "cmd": cmd,
                    "timeout_ms": timeout_ms,
                    "allow_network": allow_network,
                }
            )
            + "\n"
        )

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(socket_path)
                client.sendall(payload.encode("utf-8"))

                raw_res = b""
                while True:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    raw_res += chunk
                    if b"\n" in raw_res:
                        break

                data = json.loads(raw_res.decode("utf-8"))
                return SandboxResult(data)
        except FileNotFoundError:
            raise ConnectionError(
                f"Forkbox daemon is not running at {socket_path}. "
                "Start it with: forkbox daemon"
            )