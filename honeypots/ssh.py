"""
honeypots/ssh.py
Honeypot SSH — Servidor TCP que simula un prompt login SSH.
Captura intentos de autenticación (IP, usuario, contraseña, timestamp).
"""
import socket
import threading
import os
import time
from datetime import datetime, timezone

from colorama import Fore, Style, init as colorama_init
from core.honeypot_base import Honeypot

colorama_init(autoreset=True)

# Banner SSH por defecto
DEFAULT_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"


class SSHHoneypot(Honeypot):
    """Honeypot que simula un servidor SSH básico por TCP con Rate Limiting."""

    def __init__(self, port: int = 2222, config: dict = None):
        super().__init__(name="ssh", port=port, config=config or {})
        self._server_socket: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._rate_limit: dict[str, list[float]] = {}


    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            print(f"{Fore.YELLOW}[SSH] Ya está corriendo en el puerto {self.port}.")
            return

        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("0.0.0.0", self.port))
        self._server_socket.listen(50)
        self.running = True

        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

        print(
            f"{Fore.GREEN}[SSH] Honeypot iniciado en puerto {self.port} "
            f"{Style.DIM}(Ctrl+C para detener)"
        )

    def stop(self):
        self.running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        print(f"{Fore.RED}[SSH] Honeypot detenido.")

    # ------------------------------------------------------------------
    # Lógica interna
    # ------------------------------------------------------------------

    def _accept_loop(self):
        """Acepta conexiones entrantes en bucle."""
        while self.running:
            try:
                conn, addr = self._server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                client_thread.start()
            except OSError:
                break  # socket cerrado

    def _handle_client(self, conn: socket.socket, addr: tuple):
        """Gestiona una conexión individual: envía el banner y recoge credenciales."""
        ip = addr[0]
        
        # ── Rate Limiting ───────────────────────────────────────────────
        now = time.time()
        history = self._rate_limit.get(ip, [])
        # Limpiar history viejo (> 60s)
        history = [t for t in history if now - t < 60]
        history.append(now)
        self._rate_limit[ip] = history
        
        if len(history) > self.config.get("max_conn_per_min", 20):
            try:
                conn.sendall(b"Connection rate limit exceeded.\r\n")
                conn.close()
            except Exception:
                pass
            return

        # ── Timeout ─────────────────────────────────────────────────────
        conn.settimeout(self.config.get("timeout", 30))
        
        banner = self.config.get("banner", DEFAULT_BANNER)
        try:
            conn.sendall(f"{banner}\r\n".encode())
            conn.sendall(b"login: ")
            username = self._recv_line(conn)

            conn.sendall(b"Password: ")
            password = self._recv_line(conn)

            conn.sendall(b"Permission denied, please try again.\r\n")

            # ── Disparar evento ─────────────────────────────────────────
            self.log_event(
                ip=ip,
                data={
                    "username": username,
                    "password": password,
                    "port": self.port,
                },
            )

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _recv_line(conn: socket.socket, max_bytes: int = 256) -> str:
        """Lee bytes hasta encontrar un salto de línea."""
        data = b""
        while len(data) < max_bytes:
            byte = conn.recv(1)
            if not byte or byte in (b"\n", b"\r"):
                break
            data += byte
        return data.decode("utf-8", errors="replace").strip()
