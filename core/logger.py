"""
core/logger.py
Logger centralizado que guarda eventos en JSON Lines (logs/<name>.log).
"""
import json
import os
import threading
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")


class HoneypotLogger:
    """Escribe eventos de intrusión como JSON Lines en el fichero de log del honeypot."""

    def __init__(self, name: str):
        self.name = name
        self.log_path = os.path.join(LOG_DIR, f"{name}.log")
        self._lock = threading.Lock()
        os.makedirs(LOG_DIR, exist_ok=True)

    def log(self, ip: str, **kwargs) -> dict:
        """Registra un evento y retorna el diccionario guardado."""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "honeypot": self.name,
            "ip": ip,
            **kwargs,
        }
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        return event

    # ------------------------------------------------------------------
    # Lectura de logs
    # ------------------------------------------------------------------

    @staticmethod
    def read_all(honeypot_name: str = None) -> list[dict]:
        """Retorna todos los eventos guardados (de todos o de un honeypot concreto)."""
        events = []
        os.makedirs(LOG_DIR, exist_ok=True)

        if honeypot_name:
            files = [os.path.join(LOG_DIR, f"{honeypot_name}.log")]
        else:
            files = [
                os.path.join(LOG_DIR, f)
                for f in os.listdir(LOG_DIR)
                if f.endswith(".log")
            ]

        for path in files:
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return events
