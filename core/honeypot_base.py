"""
core/honeypot_base.py
Clase base abstracta para todos los honeypots de EasyHoneypot.
Incluye sistema de callbacks para reaccionar a eventos en tiempo real.
"""
from abc import ABC, abstractmethod
from typing import Callable
from core.logger import HoneypotLogger


class Honeypot(ABC):
    """Clase abstracta base para cualquier tipo de honeypot."""

    def __init__(self, name: str, port: int, config: dict = None):
        self.name = name
        self.port = port
        self.config = config or {}
        self.running = False
        self.logger = HoneypotLogger(name)
        self._callbacks: list[Callable[[dict], None]] = []

    # ── Ciclo de vida ──────────────────────────────────────────────────

    @abstractmethod
    def start(self):
        """Inicia el servidor honeypot."""
        pass

    @abstractmethod
    def stop(self):
        """Detiene el servidor honeypot."""
        pass

    # ── Sistema de eventos ─────────────────────────────────────────────

    def on_event(self, callback: Callable[[dict], None]) -> "Honeypot":
        """
        Registra un callback que se ejecuta cada vez que se captura un intento.

        Uso:
            hp = SSHHoneypot(port=2222)
            hp.on_event(lambda ev: print(ev["ip"]))
            hp.start()
        """
        self._callbacks.append(callback)
        return self  # fluent API

    def _fire(self, event: dict):
        """Dispara todos los callbacks registrados con el evento capturado."""
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception:
                pass  # no dejar que un callback roto detenga el honeypot

    # ── Logging + disparo de eventos ──────────────────────────────────

    def log_event(self, ip: str, data: dict) -> dict:
        """Registra un evento, lo retorna y dispara los callbacks."""
        event = self.logger.log(ip=ip, **data)
        self._fire(event)
        return event

    def __repr__(self):
        status = "RUNNING" if self.running else "STOPPED"
        return f"<{self.__class__.__name__} name={self.name} port={self.port} status={status}>"
