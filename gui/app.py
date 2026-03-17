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

LOG_DIR = os.path.join(ROOT, "logs")


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
        """Retorna los últimos N eventos en JSON."""
        limit = int(request.args.get("limit", 50))
        honeypot = request.args.get("honeypot", None)
        events = HoneypotLogger.read_all(honeypot)[:limit]
        return jsonify(events)

    @app.route("/api/alerts")
    def api_alerts():
        """Retorna alertas de seguridad."""
        honeypot = request.args.get("honeypot", None)
        alerts = AttackAnalyzer().analyze(honeypot)
        return jsonify(alerts)

    @app.route("/api/stats")
    def api_stats():
        """Estadísticas generales."""
        events = HoneypotLogger.read_all()
        total = len(events)
        by_type: dict = {}
        by_ip: dict = {}
        for e in events:
            hp = e.get("honeypot", "?")
            by_type[hp] = by_type.get(hp, 0) + 1
            ip = e.get("ip", "?")
            by_ip[ip] = by_ip.get(ip, 0) + 1

        top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:5]
        return jsonify({
            "total": total,
            "by_type": by_type,
            "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
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
