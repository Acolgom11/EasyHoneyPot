# 🍯 EasyHoneypot

> **Plataforma modular de honeypots en Python** — captura ataques reales, analiza amenazas y las visualiza en tiempo real.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()

---

## ¿Qué es?

EasyHoneypot es una herramienta de **ciberseguridad ofensiva/defensiva** que despliega servicios falsos (SSH, HTTP...) para atraer atacantes, registrar sus credenciales e identificar automáticamente el tipo de amenaza.

## ¿Para quién es?

- 🔐 **Estudiantes de ciberseguridad** que quieren ver ataques reales
- 🧪 **Investigadores** que analizan comportamiento de atacantes
- 🏠 **Sysadmins** que quieren detectar intrusiones en su red local

## ¿Por qué usarlo?

| Característica | EasyHoneypot | Otros |
|---|---|---|
| Setup en 1 comando | ✅ | ❌ |
| Dashboard en tiempo real | ✅ | Parcial |
| Análisis automático + confianza | ✅ | ❌ |
| Modo educativo (explicaciones) | ✅ | ❌ |
| Modular y extensible | ✅ | Parcial |

---

## ⚡ Instalación rápida

```bash
git clone https://github.com/tu-usuario/easyhoneypot
cd easyhoneypot/v1.0
pip install -r requirements.txt
```

---

## 🚀 Uso rápido

```bash
# Honeypot SSH en puerto 2222
python main.py start ssh --port 2222 --block

# Honeypot HTTP (login falso) en puerto 8080
python main.py start http --port 8080 --block

# Con template JSON
python main.py start --template templates/basic_ssh.json --block

# Dashboard web en tiempo real → http://localhost:5000
python main.py dashboard
```

---

## 🖥️ CLI completa

```bash
python main.py start  ssh|http  [--port N] [--template FILE] [--block]
python main.py stop   [ssh|http]
python main.py logs   [--live] [--analyze] [--limit N]
python main.py status                  # honeypots activos
python main.py stats                   # resumen de eventos
python main.py attacks                 # alertas detectadas con score
python main.py dashboard [--port N]    # dashboard web
```

---

## 📁 Estructura

```
v1.0/
├── main.py               # Punto de entrada
├── core/
│   ├── honeypot_base.py  # Clase base con sistema de eventos
│   ├── logger.py         # Logger JSON Lines thread-safe
│   ├── analyzer.py       # Detección + score de confianza
│   └── educator.py       # Explicaciones educativas por ataque
├── honeypots/
│   ├── ssh.py            # Honeypot SSH (TCP)
│   └── http_honeypot.py  # Honeypot HTTP (Flask)
├── cli/
│   └── cli.py            # CLI con rich
├── gui/
│   ├── app.py            # Backend Flask-SocketIO
│   ├── templates/        # Dashboard HTML
│   └── static/           # CSS
└── templates/            # JSON de configuración
    ├── basic_ssh.json
    ├── basic_http.json
    ├── centos_ssh.json
    ├── wordpress_http.json
    └── router_http.json
```

---

## 🔍 Tipos de ataque detectados

| Tipo | Descripción | Confianza |
|------|-------------|-----------|
| `bruteforce` | Muchos intentos misma IP en poco tiempo | Alta |
| `scan` | Pocas conexiones rápidas sin payload | Media |
| `suspicious_payload` | SQLi, XSS, comandos shell, path traversal | Alta |

---

## ⚠️ Aviso legal

Esta herramienta es solo para uso en **redes y sistemas propios** o con **autorización explícita**.
El uso en redes ajenas sin permiso es ilegal. Los autores no se responsabilizan del mal uso.

---

## 📄 Licencia

MIT © 2025 EasyHoneypot
