"""
main.py — Punto de entrada de EasyHoneypot.
Delega en la CLI de Click.

Uso:
    python main.py start ssh --port 2222 --block
    python main.py start http --port 8080 --block
    python main.py start --template templates/basic_ssh.json --block
    python main.py logs [--live] [--analyze]
    python main.py dashboard [--port 5000]
"""
import sys
import os

# Asegura que el directorio raíz esté en sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli.cli import cli

if __name__ == "__main__":
    cli()
