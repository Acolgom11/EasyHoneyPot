"""
core/honeypot_base.py
Clase base abstracta para todos los honeypots de EasyHoneypot.
"""
from abc import ABC, abstractmethod
from core.logger import HoneypotLogger


class Honeypot(ABC):
    """Clase abstracta base para cualquier tipo de honeypot."""

    def __init__(self, name: str, port: int, config: dict = None):
        self.name = name
        self.port = port
        self.config = config or {}
        self.running = False
        self.logger = HoneypotLogger(name)

    @abstractmethod
    def start(self):
        """Inicia el servidor honeypot."""
        pass

    @abstractmethod
    def stop(self):
        """Detiene el servidor honeypot."""
        pass

    def log_event(self, ip: str, data: dict):
        """Registra un evento de intrusión."""
        self.logger.log(ip=ip, **data)

    def __repr__(self):
        status = "RUNNING" if self.running else "STOPPED"
        return f"<{self.__class__.__name__} name={self.name} port={self.port} status={status}>"
