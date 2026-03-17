"""
core/analyzer.py
Analiza los logs de EasyHoneypot y detecta patrones de ataque.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from core.logger import HoneypotLogger

# Umbrales de detección
BRUTE_FORCE_THRESHOLD = 5       # intentos de la misma IP en la ventana de tiempo
BRUTE_FORCE_WINDOW_SEC = 60     # ventana en segundos
SCAN_THRESHOLD = 3              # IPs distintas con ≤ SCAN_THRESHOLD intentos (ráfaga)
SUSPICIOUS_PATTERNS = [
    r"['\";\\]",                # inyección SQL / Shell
    r"(\.\./)+",                # path traversal
    r"<\s*script",              # XSS
    r"OR\s+1=1",                # SQLi clásico
]


class AttackAnalyzer:
    """Analiza eventos de log y clasifica los ataques."""

    def analyze(self, honeypot_name: str = None) -> list[dict]:
        """
        Retorna una lista de alertas detectadas.
        Cada alerta tiene: ip, type, attempts, detail.
        """
        events = HoneypotLogger.read_all(honeypot_name)
        alerts = []

        alerts += self._detect_brute_force(events)
        alerts += self._detect_suspicious_payloads(events)
        alerts += self._detect_scan(events)

        return alerts

    # ------------------------------------------------------------------
    # Detección de fuerza bruta
    # ------------------------------------------------------------------

    def _detect_brute_force(self, events: list[dict]) -> list[dict]:
        """Detecta IPs con múltiples intentos en una ventana de tiempo corta."""
        ip_times: dict[str, list[datetime]] = defaultdict(list)

        for event in events:
            try:
                ts = datetime.fromisoformat(event["timestamp"])
            except (KeyError, ValueError):
                continue
            ip_times[event.get("ip", "?")].append(ts)

        alerts = []
        for ip, times in ip_times.items():
            times.sort()
            # Ventana deslizante simple
            for i, t in enumerate(times):
                window = [
                    x for x in times
                    if t <= x <= t + timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)
                ]
                if len(window) >= BRUTE_FORCE_THRESHOLD:
                    alerts.append({
                        "ip": ip,
                        "type": "bruteforce",
                        "attempts": len(window),
                        "detail": f"{len(window)} intentos en {BRUTE_FORCE_WINDOW_SEC}s",
                    })
                    break  # una alerta por IP

        return alerts

    # ------------------------------------------------------------------
    # Detección de payloads sospechosos
    # ------------------------------------------------------------------

    def _detect_suspicious_payloads(self, events: list[dict]) -> list[dict]:
        compiled = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_PATTERNS]
        alerts = []

        for event in events:
            for field in ("username", "password"):
                value = str(event.get(field, ""))
                for pattern in compiled:
                    if pattern.search(value):
                        alerts.append({
                            "ip": event.get("ip", "?"),
                            "type": "suspicious_payload",
                            "attempts": 1,
                            "detail": f"Campo '{field}' contiene patrón sospechoso: {value[:60]}",
                        })
                        break

        # Deduplicar por IP + tipo
        seen = set()
        deduped = []
        for a in alerts:
            key = (a["ip"], a["type"], a["detail"])
            if key not in seen:
                seen.add(key)
                deduped.append(a)
        return deduped

    # ------------------------------------------------------------------
    # Detección de escaneo
    # ------------------------------------------------------------------

    def _detect_scan(self, events: list[dict]) -> list[dict]:
        """IPs únicas con muy pocos intentos = posible escaneo automatizado."""
        ip_counts: dict[str, int] = defaultdict(int)
        for event in events:
            ip_counts[event.get("ip", "?")] += 1

        alerts = []
        for ip, count in ip_counts.items():
            if count <= SCAN_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "type": "scan",
                    "attempts": count,
                    "detail": f"Pocos intentos ({count}) — posible escaneo",
                })
        return alerts
