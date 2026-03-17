"""
core/educator.py
Modo educativo: explicaciones de cada tipo de ataque en ES e EN.
"""

EXPLANATIONS: dict[str, dict] = {
    "bruteforce": {
        "emoji": "🔨",
        "title": "Fuerza Bruta",
        "es": (
            "El atacante está probando múltiples combinaciones de usuario/contraseña "
            "de forma automatizada, esperando adivinar las credenciales correctas. "
            "Es uno de los ataques más comunes contra SSH y paneles de login."
        ),
        "en": (
            "The attacker is trying many username/password combinations automatically, "
            "hoping to guess the correct credentials. This is one of the most common "
            "attacks against SSH services and login panels."
        ),
        "mitigation_es": "Usa contraseñas largas, 2FA y bloquea IPs tras N intentos fallidos.",
        "mitigation_en": "Use long passwords, enable 2FA, and block IPs after N failed attempts.",
    },
    "scan": {
        "emoji": "🔍",
        "title": "Escaneo de Servicios",
        "es": (
            "Una herramienta automática (como Shodan, Masscan o Nmap) está probando "
            "si este puerto/servicio existe. No hay interacción humana real: "
            "es un robot buscando vulnerabilidades."
        ),
        "en": (
            "An automated tool (like Shodan, Masscan or Nmap) is probing whether "
            "this port/service is alive. There is no real human interaction — "
            "it's a bot scanning for vulnerabilities."
        ),
        "mitigation_es": "Cierra puertos innecesarios y usa un firewall para filtrar IPs externas.",
        "mitigation_en": "Close unnecessary ports and use a firewall to filter external IPs.",
    },
    "suspicious_payload": {
        "emoji": "💉",
        "title": "Payload Sospechoso",
        "es": (
            "El atacante envió datos maliciosos en el campo usuario/contraseña. "
            "Puede ser una inyección SQL (para manipular bases de datos), "
            "un ataque XSS, path traversal o comandos de shell. "
            "Indica un ataque activo y dirigido."
        ),
        "en": (
            "The attacker submitted malicious data in the username/password field. "
            "This could be SQL injection (to manipulate databases), XSS, "
            "path traversal or shell commands. This indicates an active, targeted attack."
        ),
        "mitigation_es": "Valida y sanitiza siempre los inputs. Nunca los pases directo a SQL.",
        "mitigation_en": "Always validate and sanitize inputs. Never pass them directly to SQL.",
    },
}

UNKNOWN_EXPLANATION = {
    "emoji": "⚠️",
    "title": "Ataque desconocido",
    "es": "Se detectó actividad sospechosa pero no encaja en ninguna categoría conocida.",
    "en": "Suspicious activity detected but doesn't match any known attack category.",
    "mitigation_es": "Revisa los logs manualmente para más contexto.",
    "mitigation_en": "Review the logs manually for more context.",
}


def explain(attack_type: str, lang: str = "es") -> dict:
    """
    Retorna la explicación del tipo de ataque indicado.

    Args:
        attack_type: 'bruteforce', 'scan', 'suspicious_payload'
        lang: 'es' o 'en'

    Returns:
        dict con emoji, title, explanation, mitigation
    """
    info = EXPLANATIONS.get(attack_type, UNKNOWN_EXPLANATION)
    return {
        "emoji": info["emoji"],
        "title": info["title"],
        "explanation": info.get(lang, info.get("es", "")),
        "mitigation": info.get(f"mitigation_{lang}", info.get("mitigation_es", "")),
    }


def explain_all(lang: str = "es") -> list[dict]:
    """Retorna explicaciones de todos los tipos de ataque conocidos."""
    return [
        {"type": atype, **explain(atype, lang)}
        for atype in EXPLANATIONS
    ]
