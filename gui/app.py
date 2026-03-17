"""
gui/app.py
Dashboard web de EasyHoneypot con Flask-SocketIO.
Muestra eventos en tiempo real, alertas y estado de los honeypots.
"""
import os
import sys
import json
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from core.logger import HoneypotLogger
from core.analyzer import AttackAnalyzer
import requests

LOG_DIR = os.path.join(ROOT, "logs")

# ── Caché simple de geolocalización ─────────────────────────────────────────
_geo_cache: dict = {}

def _get_geo(ip: str) -> dict:
    if ip in ("127.0.0.1", "::1", "localhost"):
        return {"country": "Local", "flag": "🏠"}
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return {"country": "LAN", "flag": "🔌"}
        
    if ip not in _geo_cache:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country", timeout=2)
            if r.status_code == 200:
                data = r.json()
                code = data.get("countryCode", "")
                # Convertir código de país a emoji bandera
                flag = "".join(chr(127397 + ord(c)) for c in code) if code else "🌍"
                _geo_cache[ip] = {"country": data.get("country", "Unknown"), "flag": flag}
            else:
                _geo_cache[ip] = {"country": "Unknown", "flag": "🌍"}
        except Exception:
            _geo_cache[ip] = {"country": "Unknown", "flag": "🌍"}
            
    return _geo_cache[ip]

def _enrich_event(event: dict, analyzer: AttackAnalyzer) -> dict:
    # Añadir Geo
    geo = _get_geo(event.get("ip", ""))
    event["country"] = geo["country"]
    event["flag"] = geo["flag"]
    # Añadir amenaza
    event["threat"] = None
    alerts = analyzer.analyze(event.get("honeypot"))
    for a in alerts:
        if a["ip"] == event.get("ip"):
            event["threat"] = a["type"]
            break
    return event


def create_app():
    """Crea y configura la aplicación Flask + SocketIO."""
    template_folder = os.path.join(os.path.dirname(__file__), "templates")
    static_folder = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.secret_key = "easyhoneypot-dashboard-secret"
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # ── Rutas HTTP ─────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/events")
    def api_events():
        """Retorna los últimos N eventos en JSON (enriquecidos con Geo y Amenaza)."""
        limit = int(request.args.get("limit", 50))
        honeypot = request.args.get("honeypot", None)
        events = HoneypotLogger.read_all(honeypot)[:limit]
        
        analyzer = AttackAnalyzer()
        enriched = [_enrich_event(e.copy(), analyzer) for e in events]
        return jsonify(enriched)

    @app.route("/api/alerts")
    def api_alerts():
        """Retorna alertas de seguridad."""
        honeypot = request.args.get("honeypot", None)
        alerts = AttackAnalyzer().analyze(honeypot)
        return jsonify(alerts)
        
    @app.route("/api/explain")
    def api_explain():
        """Retorna las explicaciones educativas de los tipos de ataque."""
        from core.educator import explain_all
        lang = request.args.get("lang", "es")
        return jsonify(explain_all(lang))

    @app.route("/api/stats")
    def api_stats():
        """Estadísticas generales."""
        events = HoneypotLogger.read_all()
        total = len(events)
        by_type: dict = {}
        by_ip: dict = {}
        
        # Para gráfica temporal: eventos por minuto
        # (últimos 60 minutos)
        now = time.time()
        timeline = {}
        
        for e in events:
            hp = e.get("honeypot", "?")
            by_type[hp] = by_type.get(hp, 0) + 1
            ip = e.get("ip", "?")
            by_ip[ip] = by_ip.get(ip, 0) + 1
            
            # Extraer minuto (MM)
            ts_str = e.get("timestamp", "")
            if ts_str:
                try:
                    minute = ts_str[11:16] # 'HH:MM'
                    timeline[minute] = timeline.get(minute, 0) + 1
                except: pass

        top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]
        # Ordenar timeline cronológicamente (últimos 20 minutos con tráfico)
        timeline_sorted = dict(sorted(timeline.items())[-20:])

        return jsonify({
            "total": total,
            "by_type": by_type,
            "top_ips": [{"ip": ip, "count": c, **_get_geo(ip)} for ip, c in top_ips],
            "timeline": timeline_sorted
        })

    # ── SocketIO — live feed ───────────────────────────────────────────────

    _last_event_count = [0]

    def watch_logs():
        """Hilo que vigila los logs y emite nuevos eventos por WebSocket."""
        while True:
            events = HoneypotLogger.read_all()
            current_count = len(events)
            if current_count > _last_event_count[0]:
                new_events = events[: current_count - _last_event_count[0]]
                _last_event_count[0] = current_count
                for ev in reversed(new_events):
                    socketio.emit("new_event", ev, namespace="/")
            time.sleep(1.5)

    watcher = threading.Thread(target=watch_logs, daemon=True)
    watcher.start()

    return app, socketio
