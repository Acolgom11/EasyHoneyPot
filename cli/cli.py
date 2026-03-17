"""
cli/cli.py
CLI de EasyHoneypot construida con Click.
Comandos: start, stop, logs, dashboard
"""
import sys
import os
import time
import json as _json
import signal
import threading

import click
from colorama import Fore, Style, Back, init as colorama_init
from tabulate import tabulate

# Añadir el directorio raíz al path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

colorama_init(autoreset=True)

# Registro de honeypots activos (nombre -> instancia)
_active_honeypots: dict = {}

# ── Helpers de presentación ────────────────────────────────────────────────

BANNER = f"""
{Fore.CYAN}  _____ {Fore.MAGENTA}_   _                       ___        _
{Fore.CYAN} | ____| | | |{Fore.MAGENTA}  ___  _ __   ___   / _ \\  ___| |_
{Fore.CYAN} |  _| | |_| |{Fore.MAGENTA} / _ \\| '_ \\ / _ \\ | | | |/ _ \\ __|
{Fore.CYAN} | |___|  _  |{Fore.MAGENTA}|  __/| | | |  __/ | |_| |  __/ |_
{Fore.CYAN} |_____|_| |_|{Fore.MAGENTA} \\___||_| |_|\\___|  \\___/ \\___|\\__|
{Style.DIM}                    EasyHoneypot v1.0
"""


def print_banner():
    click.echo(BANNER)


def _load_template(template_path: str) -> dict:
    """Carga un template JSON para configurar un honeypot."""
    if not os.path.exists(template_path):
        # Buscar en la carpeta templates del proyecto
        candidate = os.path.join(ROOT, "templates", template_path)
        if os.path.exists(candidate):
            template_path = candidate
        else:
            click.echo(f"{Fore.RED}[ERROR] Template no encontrado: {template_path}")
            sys.exit(1)

    with open(template_path, "r", encoding="utf-8") as f:
        return _json.load(f)


# ── Grupo principal ────────────────────────────────────────────────────────

@click.group()
def cli():
    """EasyHoneypot — Herramienta de honeypots modular en Python."""
    pass


# ── Comando: start ─────────────────────────────────────────────────────────

@cli.command()
@click.argument("honeypot_type", required=False, default=None)
@click.option("--port", "-p", default=None, type=int, help="Puerto de escucha")
@click.option("--template", "-t", default=None, help="Ruta a un fichero de template JSON")
@click.option("--block", "-b", is_flag=True, default=False,
              help="Mantener el proceso bloqueado hasta Ctrl+C")
def start(honeypot_type, port, template, block):
    """Inicia un honeypot (ssh | http) o carga un --template JSON."""
    print_banner()

    config = {}
    if template:
        config = _load_template(template)
        if not honeypot_type:
            honeypot_type = config.get("type")
        if port is None:
            port = config.get("port")

    if not honeypot_type:
        click.echo(f"{Fore.RED}[ERROR] Especifica un tipo: ssh, http (o usa --template)")
        sys.exit(1)

    honeypot_type = honeypot_type.lower()

    # Resolver puerto por defecto según tipo
    if port is None:
        port = 2222 if honeypot_type == "ssh" else 8080

    hp = _create_honeypot(honeypot_type, port, config)
    _active_honeypots[honeypot_type] = hp
    hp.start()

    if block:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            hp.stop()
            click.echo(f"\n{Fore.YELLOW}Honeypot detenido.")


def _create_honeypot(htype: str, port: int, config: dict):
    """Instancia el honeypot correcto según el tipo."""
    if htype == "ssh":
        from honeypots.ssh import SSHHoneypot
        return SSHHoneypot(port=port, config=config)
    elif htype == "http":
        from honeypots.http_honeypot import HTTPHoneypot
        return HTTPHoneypot(port=port, config=config)
    else:
        click.echo(f"{Fore.RED}[ERROR] Tipo desconocido: {htype}. Usa 'ssh' o 'http'.")
        sys.exit(1)


# ── Comando: stop ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("honeypot_type", required=False, default=None)
def stop(honeypot_type):
    """Detiene un honeypot activo."""
    if not _active_honeypots:
        click.echo(f"{Fore.YELLOW}No hay honeypots activos en esta sesión.")
        return

    targets = (
        {honeypot_type: _active_honeypots[honeypot_type]}
        if honeypot_type and honeypot_type in _active_honeypots
        else _active_honeypots.copy()
    )

    for name, hp in targets.items():
        hp.stop()
        _active_honeypots.pop(name, None)


# ── Comando: logs ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--honeypot", "-H", default=None, help="Filtrar por tipo (ssh, http)")
@click.option("--live", "-l", is_flag=True, default=False,
              help="Modo live: refrescar cada 2 segundos")
@click.option("--analyze", "-a", is_flag=True, default=False,
              help="Mostrar análisis de ataques detectados")
@click.option("--limit", "-n", default=20, show_default=True,
              help="Número máximo de entradas a mostrar")
def logs(honeypot, live, analyze, limit):
    """Muestra los logs capturados por los honeypots."""
    from core.logger import HoneypotLogger
    from core.analyzer import AttackAnalyzer

    def _render():
        click.clear()
        events = HoneypotLogger.read_all(honeypot)[:limit]

        if not events:
            click.echo(f"{Fore.YELLOW}No hay eventos registrados aún.")
        else:
            rows = []
            for e in events:
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                rows.append([
                    ts,
                    Fore.CYAN + e.get("honeypot", "?") + Style.RESET_ALL,
                    Fore.WHITE + e.get("ip", "?") + Style.RESET_ALL,
                    Fore.YELLOW + str(e.get("username", e.get("user", "-"))) + Style.RESET_ALL,
                    Fore.MAGENTA + str(e.get("password", "-")) + Style.RESET_ALL,
                ])

            click.echo(f"\n{Fore.GREEN}{'─'*60}")
            click.echo(f"  📋 EasyHoneypot — Eventos capturados ({len(events)} de {len(HoneypotLogger.read_all(honeypot))})")
            click.echo(f"{Fore.GREEN}{'─'*60}\n")
            click.echo(tabulate(
                rows,
                headers=["Timestamp", "Tipo", "IP", "Usuario", "Password"],
                tablefmt="fancy_grid",
            ))

        if analyze:
            alerts = AttackAnalyzer().analyze(honeypot)
            if alerts:
                click.echo(f"\n{Fore.RED}{'─'*60}")
                click.echo(f"  🚨 Alertas de seguridad ({len(alerts)} detectadas)")
                click.echo(f"{Fore.RED}{'─'*60}\n")
                alert_rows = [
                    [
                        Fore.RED + a["type"] + Style.RESET_ALL,
                        a["ip"],
                        str(a["attempts"]),
                        a["detail"][:70],
                    ]
                    for a in alerts
                ]
                click.echo(tabulate(
                    alert_rows,
                    headers=["Tipo ataque", "IP", "Intentos", "Detalle"],
                    tablefmt="fancy_grid",
                ))
            else:
                click.echo(f"\n{Fore.GREEN}✅ No se detectaron ataques significativos.")

    if live:
        click.echo(f"{Fore.CYAN}Modo live activado. Ctrl+C para salir.")
        try:
            while True:
                _render()
                time.sleep(2)
        except KeyboardInterrupt:
            click.echo(f"\n{Fore.YELLOW}Saliendo del modo live.")
    else:
        _render()


# ── Comando: dashboard ─────────────────────────────────────────────────────

@cli.command()
@click.option("--port", "-p", default=5000, show_default=True, help="Puerto del dashboard")
def dashboard(port):
    """Lanza el dashboard web en http://localhost:<port>"""
    from gui.app import create_app
    print_banner()
    click.echo(f"{Fore.CYAN}🌐 Dashboard disponible en: {Fore.WHITE}http://localhost:{port}")
    app, socketio = create_app()
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)
