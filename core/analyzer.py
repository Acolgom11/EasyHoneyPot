"""
core/analyzer.py
Analiza los logs de EasyHoneypot y detecta patrones de ataque.
Cada alerta incluye un score de confianza (0.0 – 1.0).
"""
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from core.logger import HoneypotLogger

# ── Umbrales de detección ─────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5       # intentos de la misma IP en la ventana
BRUTE_FORCE_WINDOW_SEC = 60     # ventana en segundos
BRUTE_FORCE_MAX = 50            # intentos para confidence=1.0
SCAN_THRESHOLD = 3              # ≤ N intentos por IP = posible escaneo

# ── Patrones de payload sospechoso ────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    # SQLi
    (r"'\s*OR\s+['\"]?1['\"]?\s*=\s*['\"]?1",  "SQLi clásico (OR 1=1)"),
    (r"(--|#|/\*)\s*$",                           "Comentario SQL"),
    (r"UNION\s+SELECT",                           "SQLi UNION SELECT"),
    (r"DROP\s+TABLE",                             "SQLi DROP TABLE"),
    # XSS
    (r"<\s*script",                               "XSS script tag"),
    (r"javascript\s*:",                           "XSS javascript:"),
    # Path traversal
    (r"(\.\./){2,}",                              "Path traversal"),
    # Shell injection
    (r";\s*(ls|cat|id|whoami|wget|curl|bash|sh)\b", "Inyección de comandos shell"),
    (r"&&\s*(ls|cat|id|whoami|wget|curl|bash|sh)\b", "Inyección && shell"),
    (r"\|\s*(ls|cat|id|whoami|wget|curl|bash)\b",    "Pipe shell injection"),
    # Otros
    (r"['\";\\]",                                 "Caracteres de inyección"),
]

_COMPILED = [
    (re.compile(p, re.IGNORECASE), desc)
    for p, desc in SUSPICIOUS_PATTERNS
]


class AttackAnalyzer:
    """Analiza eventos de log y clasifica los ataques con score de confianza."""

    def analyze(self, honeypot_name: str = None) -> list[dict]:
        """
        Retorna lista de alertas detectadas.
        Cada alerta: {ip, type, attempts, detail, confidence}
        """
        events = HoneypotLogger.read_all(honeypot_name)
        alerts: list[dict] = []

        alerts += self._detect_brute_force(events)
        alerts += self._detect_suspicious_payloads(events)
        alerts += self._detect_scan(events)

        # Ordenar por confianza descendente
        alerts.sort(key=lambda a: a["confidence"], reverse=True)
        return alerts

    # ── Fuerza bruta ──────────────────────────────────────────────────────

    def _detect_brute_force(self, events: list[dict]) -> list[dict]:
        """IPs con múltiples intentos en una ventana de tiempo corta."""
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
            for t in times:
                window = [
                    x for x in times
                    if t <= x <= t + timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)
                ]
                if len(window) >= BRUTE_FORCE_THRESHOLD:
                    # Confianza: sube linealmente hasta BRUTE_FORCE_MAX intentos
                    confidence = min(1.0, len(window) / BRUTE_FORCE_MAX)
                    alerts.append({
                        "ip": ip,
                        "type": "bruteforce",
                        "attempts": len(window),
                        "detail": f"{len(window)} intentos en {BRUTE_FORCE_WINDOW_SEC}s",
                        "confidence": round(confidence, 2),
                    })
                    break  # una alerta por IP

        return alerts

    # ── Payloads sospechosos ───────────────────────────────────────────────

    def _detect_suspicious_payloads(self, events: list[dict]) -> list[dict]:
        """Busca patrones de inyección en username/password."""
        alerts = []
        seen: set[tuple] = set()

        for event in events:
            for field in ("username", "password"):
                value = str(event.get(field, ""))
                for pattern, description in _COMPILED:
                    if pattern.search(value):
                        ip = event.get("ip", "?")
                        key = (ip, description, value[:40])
                        if key in seen:
                            continue
                        seen.add(key)

                        # Confianza: alta si el patrón es muy específico
                        is_specific = any(
                            kw in description
                            for kw in ("SQLi", "XSS", "shell", "PATH", "UNION", "DROP")
                        )
                        confidence = 0.90 if is_specific else 0.65

                        alerts.append({
                            "ip": ip,
                            "type": "suspicious_payload",
                            "attempts": 1,
                            "detail": f"{description} en campo '{field}': {value[:60]}",
                            "confidence": confidence,
                        })
                        break  # un patrón por campo por evento

        return alerts

    # ── Escaneo ───────────────────────────────────────────────────────────

    def _detect_scan(self, events: list[dict]) -> list[dict]:
        """IPs con muy pocos intentos = posible escaneo automatizado."""
        ip_counts: dict[str, int] = defaultdict(int)
        for event in events:
            ip_counts[event.get("ip", "?")] += 1

        alerts = []
        for ip, count in ip_counts.items():
            if count <= SCAN_THRESHOLD:
                # Más bajo el count, más probable que sea un scanner
                confidence = round(0.4 + (SCAN_THRESHOLD - count) * 0.1, 2)
                alerts.append({
                    "ip": ip,
                    "type": "scan",
                    "attempts": count,
                    "detail": f"{count} intento(s) — posible escaneo automatizado",
                    "confidence": confidence,
                })

        return alerts
