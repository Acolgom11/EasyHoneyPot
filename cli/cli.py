"""
cli/cli.py
CLI de EasyHoneypot — construida con Click + Rich.
Comandos: start, stop, logs, status, stats, attacks, dashboard
"""
import sys
import os
import time
import json as _json
import threading

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Spinner
from rich.align import Align

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import sys as _sys
import io as _io
_sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding='utf-8')

console = Console()

# Registro de honeypots activos en la sesión
_active_honeypots: dict = {}

# ── Helpers visuales ───────────────────────────────────────────────────────

BANNER = """[bold cyan]
  ███████╗ █████╗ ███████╗██╗   ██╗
  ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝
  █████╗  ███████║███████╗ ╚████╔╝ 
  ██╔══╝  ██╔══██║╚════██║  ╚██╔╝  
  ███████╗██║  ██║███████║   ██║   
  ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   [/bold cyan]
[bold magenta]  🍯 HoneyPot  [/bold magenta][dim]v1.0 — Modular Honeypot Framework[/dim]
"""

LEGAL_WARNING = Panel(
    "[bold yellow]⚠️  AVISO LEGAL[/bold yellow]\n\n"
    "Esta herramienta debe usarse [bold]únicamente en redes y sistemas propios[/bold]\n"
    "o con [bold]autorización explícita por escrito[/bold] del propietario.\n\n"
    "[dim]El uso no autorizado en redes ajenas puede ser [red]ilegal[/red].[/dim]",
    border_style="yellow",
    width=60,
)

CONFIDENCE_COLORS = {
    (0.0, 0.4): "dim",
    (0.4, 0.7): "yellow",
    (0.7, 0.9): "orange3",
    (0.9, 1.01): "bold red",
}

TYPE_STYLES = {
    "bruteforce":         "[bold red]🔨 bruteforce[/bold red]",
    "scan":               "[yellow]🔍 scan[/yellow]",
    "suspicious_payload": "[bold magenta]💉 payload[/bold magenta]",
}
HP_STYLES = {
    "ssh":  "[bold cyan]SSH[/bold cyan]",
    "http": "[bold magenta]HTTP[/bold magenta]",
}


def _confidence_style(conf: float) -> str:
    for (lo, hi), style in CONFIDENCE_COLORS.items():
        if lo <= conf < hi:
            return f"[{style}]{conf:.0%}[/{style}]"
    return str(conf)


def _print_banner():
    console.print(BANNER)


def _load_template(template_path: str) -> dict:
    if not os.path.exists(template_path):
        candidate = os.path.join(ROOT, "templates", template_path)
        if os.path.exists(candidate):
            template_path = candidate
        else:
            console.print(f"[red][ERROR] Template no encontrado: {template_path}[/red]")
            sys.exit(1)
    with open(template_path, "r", encoding="utf-8") as f:
        return _json.load(f)


def _create_honeypot(htype: str, port: int, config: dict):
    if htype == "ssh":
        from honeypots.ssh import SSHHoneypot
        return SSHHoneypot(port=port, config=config)
    elif htype == "http":
        from honeypots.http_honeypot import HTTPHoneypot
        return HTTPHoneypot(port=port, config=config)
    else:
        console.print(f"[red][ERROR] Tipo desconocido: {htype}. Usa 'ssh' o 'http'.[/red]")
        sys.exit(1)


# ── Grupo principal ────────────────────────────────────────────────────────

@click.group()
def cli():
    """EasyHoneypot — Herramienta de honeypots modular en Python."""
    pass


# ── start ──────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("honeypot_type", required=False, default=None)
@click.option("--port", "-p", default=None, type=int)
@click.option("--template", "-t", default=None)
@click.option("--block", "-b", is_flag=True, default=False)
def start(honeypot_type, port, template, block):
    """Inicia un honeypot (ssh | http) o carga un --template JSON."""
    _print_banner()
    console.print(LEGAL_WARNING)
    console.print()

    config = {}
    if template:
        config = _load_template(template)
        if not honeypot_type:
            honeypot_type = config.get("type")
        if port is None:
            port = config.get("port")

    if not honeypot_type:
        console.print("[red][ERROR] Especifica un tipo: ssh, http  (o usa --template)[/red]")
        sys.exit(1)

    honeypot_type = honeypot_type.lower()
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
            console.print("\n[yellow]Honeypot detenido.[/yellow]")


# ── stop ───────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("honeypot_type", required=False, default=None)
def stop(honeypot_type):
    """Detiene un honeypot activo."""
    if not _active_honeypots:
        console.print("[yellow]No hay honeypots activos en esta sesión.[/yellow]")
        return
    targets = (
        {honeypot_type: _active_honeypots[honeypot_type]}
        if honeypot_type and honeypot_type in _active_honeypots
        else _active_honeypots.copy()
    )
    for name, hp in targets.items():
        hp.stop()
        _active_honeypots.pop(name, None)


# ── status ─────────────────────────────────────────────────────────────────

@cli.command()
def status():
    """Muestra los honeypots activos en la sesión actual."""
    _print_banner()
    if not _active_honeypots:
        console.print(Panel("[yellow]No hay honeypots activos en esta sesión.[/yellow]",
                             title="Estado", border_style="yellow"))
        return

    table = Table(title="🟢 Honeypots activos", box=box.ROUNDED, border_style="cyan")
    table.add_column("Tipo", style="bold")
    table.add_column("Puerto", justify="right")
    table.add_column("Estado")

    for name, hp in _active_honeypots.items():
        status_txt = "[bold green]● RUNNING[/bold green]" if hp.running else "[red]○ STOPPED[/red]"
        table.add_row(HP_STYLES.get(name, name), str(hp.port), status_txt)

    console.print(table)


# ── stats ──────────────────────────────────────────────────────────────────

@cli.command()
def stats():
    """Resumen estadístico de todos los eventos capturados."""
    from core.logger import HoneypotLogger
    _print_banner()

    events = HoneypotLogger.read_all()
    if not events:
        console.print("[yellow]Sin eventos registrados aún.[/yellow]")
        return

    by_type: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for e in events:
        hp = e.get("honeypot", "?")
        by_type[hp] = by_type.get(hp, 0) + 1
        by_ip[e.get("ip", "?")] = by_ip.get(e.get("ip", "?"), 0) + 1

    top_ips = sorted(by_ip.items(), key=lambda x: x[1], reverse=True)[:10]

    # ── resumen global ──
    summary = Table(box=box.SIMPLE_HEAD, show_header=False, border_style="cyan")
    summary.add_column("Métrica", style="dim")
    summary.add_column("Valor", style="bold")
    summary.add_row("Total eventos", str(len(events)))
    for hp_type, count in by_type.items():
        label = HP_STYLES.get(hp_type, hp_type)
        summary.add_row(f"  → {hp_type.upper()}", str(count))
    console.print(Panel(summary, title="📊 Resumen global", border_style="cyan"))

    # ── top IPs ──
    ip_table = Table(title="🏴‍☠️ Top IPs atacantes", box=box.ROUNDED, border_style="red")
    ip_table.add_column("#", style="dim", justify="right")
    ip_table.add_column("IP", style="bold cyan")
    ip_table.add_column("Intentos", justify="right", style="bold")

    for i, (ip, count) in enumerate(top_ips, 1):
        ip_table.add_row(str(i), ip, str(count))

    console.print(ip_table)


# ── attacks ────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--honeypot", "-H", default=None)
@click.option("--explain", "-e", is_flag=True, default=False,
              help="Mostrar explicación educativa de cada tipo de ataque")
@click.option("--lang", default="es", show_default=True,
              help="Idioma de las explicaciones: es | en")
def attacks(honeypot, explain, lang):
    """Lista las amenazas detectadas con score de confianza."""
    from core.analyzer import AttackAnalyzer
    from core.educator import explain as edu_explain
    _print_banner()

    alerts = AttackAnalyzer().analyze(honeypot)

    if not alerts:
        console.print(Panel("[green]✅ Sin amenazas detectadas.[/green]",
                             border_style="green"))
        return

    table = Table(title=f"🚨 Amenazas detectadas ({len(alerts)})",
                  box=box.ROUNDED, border_style="red")
    table.add_column("Confianza", justify="center", width=10)
    table.add_column("Tipo", width=20)
    table.add_column("IP", style="cyan")
    table.add_column("Intentos", justify="right")
    table.add_column("Detalle")

    for a in alerts:
        conf_str = _confidence_style(a.get("confidence", 0.0))
        type_str = TYPE_STYLES.get(a["type"], a["type"])
        table.add_row(
            conf_str,
            type_str,
            a["ip"],
            str(a["attempts"]),
            a["detail"][:70],
        )

    console.print(table)

    if explain:
        console.print()
        seen_types: set[str] = set()
        for a in alerts:
            atype = a["type"]
            if atype in seen_types:
                continue
            seen_types.add(atype)
            info = edu_explain(atype, lang)
            panel_content = (
                f"[bold]{info['explanation']}[/bold]\n\n"
                f"[dim]💡 Mitigación:[/dim] {info['mitigation']}"
            )
            console.print(Panel(
                panel_content,
                title=f"{info['emoji']} {info['title']}",
                border_style="yellow",
                width=80,
            ))


# ── logs ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--honeypot", "-H", default=None)
@click.option("--live", "-l", is_flag=True, default=False)
@click.option("--analyze", "-a", is_flag=True, default=False)
@click.option("--limit", "-n", default=25, show_default=True)
@click.option("--explain", "-e", is_flag=True, default=False, help="Mostrar paneles educativos (junto a --analyze)")
@click.option("--lang", default="es", show_default=True, help="Idioma de las explicaciones (es/en)")
def logs(honeypot, live, analyze, limit, explain, lang):
    """Muestra los logs capturados (con --live y --analyze opcionales)."""
    from core.logger import HoneypotLogger
    from core.analyzer import AttackAnalyzer
    from core.educator import explain as edu_explain

    def _render():
        console.clear()
        events = HoneypotLogger.read_all(honeypot)[:limit]

        if not events:
            console.print("[yellow]Sin eventos registrados aún.[/yellow]")
        else:
            table = Table(
                title=f"📋 Eventos capturados ({len(events)} / {len(HoneypotLogger.read_all(honeypot))})",
                box=box.ROUNDED, border_style="cyan",
            )
            table.add_column("Timestamp", style="dim", width=20)
            table.add_column("Tipo", width=7)
            table.add_column("IP", style="bold cyan")
            table.add_column("Usuario", style="yellow")
            table.add_column("Contraseña", style="magenta")
            table.add_column("Extra", style="dim")

            for e in events:
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                hp_badge = HP_STYLES.get(e.get("honeypot", "?"), "?")
                extra = e.get("user_agent", "")[:40] or "—"
                table.add_row(
                    ts, hp_badge,
                    e.get("ip", "?"),
                    str(e.get("username", e.get("user", "—"))),
                    str(e.get("password", "—")),
                    extra,
                )
            console.print(table)

        if analyze:
            alerts = AttackAnalyzer().analyze(honeypot)
            if alerts:
                atk_table = Table(
                    title=f"🚨 Alertas ({len(alerts)})",
                    box=box.SIMPLE_HEAD, border_style="red",
                )
                atk_table.add_column("Conf.", justify="center", width=8)
                atk_table.add_column("Tipo", width=22)
                atk_table.add_column("IP", style="cyan")
                atk_table.add_column("Detalle")
                for a in alerts:
                    atk_table.add_row(
                        _confidence_style(a.get("confidence", 0)),
                        TYPE_STYLES.get(a["type"], a["type"]),
                        a["ip"],
                        a["detail"][:60],
                    )
                console.print(atk_table)
                
                if explain:
                    console.print()
                    seen_types: set[str] = set()
                    for a in alerts:
                        atype = a["type"]
                        if atype in seen_types:
                            continue
                        seen_types.add(atype)
                        info = edu_explain(atype, lang)
                        panel_content = (
                            f"[bold]{info['explanation']}[/bold]\n\n"
                            f"[dim]💡 Mitigación:[/dim] {info['mitigation']}"
                        )
                        console.print(Panel(
                            panel_content,
                            title=f"{info['emoji']} {info['title']}",
                            border_style="yellow",
                            width=80,
                        ))
            else:
                console.print("[green]✅ Sin amenazas detectadas.[/green]")

    if live:
        console.print("[cyan]Modo live activo. Ctrl+C para salir.[/cyan]")
        try:
            while True:
                _render()
                time.sleep(2)
        except KeyboardInterrupt:
            console.print("\n[yellow]Saliendo del modo live.[/yellow]")
    else:
        _render()


# ── dashboard ──────────────────────────────────────────────────────────────

@cli.command()
@click.option("--port", "-p", default=5000, show_default=True)
def dashboard(port):
    """Lanza el dashboard web en http://localhost:<port>"""
    from gui.app import create_app
    _print_banner()
    console.print(Panel(
        f"[bold cyan]🌐 Dashboard disponible en:[/bold cyan] [link]http://localhost:{port}[/link]\n"
        "[dim]Ctrl+C para detener[/dim]",
        border_style="cyan",
    ))
    app, socketio = create_app()
    socketio.run(app, host="0.0.0.0", port=port, debug=False, use_reloader=False)
