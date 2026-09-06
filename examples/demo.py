import socket
import json

SOCKET_PATH = "/tmp/forkbox.sock"

class SandboxResult:
    def __init__(self, data: dict):
        self.exit_code = data.get("exit_code", -1)
        self.stdout = data.get("stdout", "")
        self.stderr = data.get("stderr", "")
        self.timed_out = data.get("timed_out", False)
        self.duration_ms = data.get("duration_us", 0) / 1000.0

    def __repr__(self):
        return f"<SandboxResult code={self.exit_code} time={self.duration_ms:.2f}ms timed_out={self.timed_out}>"

class Forkbox:
    @staticmethod
    def run(cmd: str, timeout_ms: int = 3000, allow_network: bool = False) -> SandboxResult:
        payload = json.dumps({
            "cmd": cmd,
            "timeout_ms": timeout_ms,
            "allow_network": allow_network
        }) + "\n"

        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(SOCKET_PATH)
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

if __name__ == "__main__":
    print("=== TESTE DO CLIENTE FORKBOX EM PYTHON ===")
    
    # 1. Execução de script Python em sandbox isolada
    print("\n[1] Executando script computacional em Python...")
    res = Forkbox.run("python3 -c 'import math; print(\"Fatorial de 20:\", math.factorial(20))'")
    print("↳", res)
    if res.stdout:
        print("↳ Output:", res.stdout.strip())
    if res.stderr:
        print("↳ Stderr/Erro:", res.stderr.strip())

    # 2. Contenção de loop infinito (Timeout)
    print("\n[2] Testando contenção de loop infinito...")
    res_timeout = Forkbox.run("while true; do :; done", timeout_ms=500)
    print("↳", res_timeout)
    print(f"↳ Interrompido por timeout: {res_timeout.timed_out} (Exit: {res_timeout.exit_code})")