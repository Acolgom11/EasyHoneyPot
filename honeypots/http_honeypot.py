"""
honeypots/http_honeypot.py
Honeypot HTTP — Servidor web falso con formulario de login.
Captura IP, usuario, contraseña y User-Agent.
"""
import threading
from flask import Flask, request, redirect, url_for, render_template_string
from colorama import Fore, Style, init as colorama_init
from core.honeypot_base import Honeypot

colorama_init(autoreset=True)

# ── Plantilla del formulario de login falso ────────────────────────────────
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} — Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0f172a;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
    font-family: 'Segoe UI', sans-serif;
    color: #e2e8f0;
  }
  .card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 25px 50px rgba(0,0,0,.6);
  }
  h2 { font-size: 1.4rem; margin-bottom: 1.5rem; color: #f8fafc; text-align:center; }
  label { display: block; font-size: .8rem; color: #94a3b8; margin-bottom: .3rem; margin-top:1rem; }
  input {
    width: 100%; padding: .65rem .9rem;
    background: #0f172a; border: 1px solid #475569;
    border-radius: 8px; color: #f1f5f9; font-size: .95rem;
    outline: none; transition: border .2s;
  }
  input:focus { border-color: #6366f1; }
  button {
    margin-top: 1.5rem; width: 100%;
    padding: .75rem; background: #6366f1;
    border: none; border-radius: 8px;
    color: #fff; font-size: 1rem; font-weight: 600;
    cursor: pointer; transition: background .2s;
  }
  button:hover { background: #4f46e5; }
  .error { color: #f87171; font-size:.83rem; margin-top:.6rem; text-align:center; }
  .brand { text-align:center; font-size:.75rem; color:#475569; margin-top:1.5rem; }
</style>
</head>
<body>
  <div class="card">
    <h2>🔒 {{ title }}</h2>
    <form method="POST" action="/login">
      <label>Usuario</label>
      <input type="text" name="username" autofocus placeholder="admin" required>
      <label>Contraseña</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit">Iniciar sesión</button>
      {% if error %}<p class="error">{{ error }}</p>{% endif %}
    </form>
    <p class="brand">Panel de Administración v2.4.1</p>
  </div>
</body>
</html>
"""

# ── Plantilla del falso panel admin ───────────────────────────────────────
ADMIN_HTML = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>{{ title }} — Dashboard</title>
<style>
  body { background:#0f172a; color:#e2e8f0; font-family:'Segoe UI',sans-serif;
         display:flex; flex-direction:column; align-items:center;
         justify-content:center; min-height:100vh; }
  .box { background:#1e293b; border:1px solid #334155; border-radius:12px;
         padding:2rem 2.5rem; text-align:center; max-width:500px; }
  h2 { color:#f8fafc; margin-bottom:1rem; }
  p { color:#94a3b8; line-height:1.6; }
  .badge { display:inline-block; margin-top:1rem; padding:.4rem 1rem;
           background:#6366f1; border-radius:20px; font-size:.85rem; color:#fff; }
</style>
</head>
<body>
  <div class="box">
    <h2>✅ Bienvenido al Panel de Administración</h2>
    <p>Sistema operativo correctamente. Cargando módulos de gestión...</p>
    <span class="badge">Sesión activa · Rol: Administrador</span>
  </div>
</body>
</html>
"""


# ── Plantillas adicionales ────────────────────────────────────────────────
ROUTER_HTML = """
<!DOCTYPE html>
<html><head><title>Router Login</title>
<style>
body { font-family: sans-serif; background:#f0f0f0; display:flex; justify-content:center; align-items:center; height:100vh; margin:0; }
.box { background:#fff; border:1px solid #ccc; padding:30px; border-radius:4px; box-shadow:0 0 10px rgba(0,0,0,0.1); width:320px; }
h3 { margin-top:0; color:#333; text-align:center; border-bottom:1px solid #eee; padding-bottom:10px; }
input { width:100%; padding:8px; margin:10px 0; box-sizing:border-box; border:1px solid #aaa; }
button { width:100%; padding:10px; background:#005bb5; color:white; border:none; cursor:pointer; font-weight:bold; }
button:hover { background:#004494; }
</style></head>
<body>
  <div class="box">
    <h3>Wireless Router Admin</h3>
    <form method="POST" action="/login">
      <input type="text" name="username" placeholder="Username" required autofocus>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Log In</button>
    </form>
  </div>
</body></html>
"""

WP_HTML = """
<!DOCTYPE html>
<html lang="en-US">
<head>
  <title>Log In &lsaquo; WordPress</title>
  <style>
    body{ background:#f1f1f1; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;
          display:flex; justify-content:center; padding-top:8%; }
    .login{ width:320px; }
    .box{ background:#fff; border:1px solid #c3c4c7; box-shadow:0 1px 3px rgba(0,0,0,.04); padding:26px 24px 46px; }
    label{ font-size:14px; color:#3c434a; display:block; margin-bottom:5px; }
    input[type=text], input[type=password]{ width:100%; padding:0 8px; line-height:2; font-size:24px; border:1px solid #8c8f94; border-radius:4px; margin-bottom:16px; box-sizing:border-box;}
    button{ background:#2271b1; border:1px solid #2271b1; color:#fff; cursor:pointer; padding:4px 12px; font-size:13px; font-weight:600; line-height:2; border-radius:3px; float:right; }
  </style>
</head>
<body class="login">
  <div class="login">
    <div class="box">
      <form method="POST" action="/wp-login.php">
        <label>Username or Email Address</label>
        <input type="text" name="username" required>
        <label>Password</label>
        <input type="password" name="password" required>
        <button type="submit">Log In</button>
      </form>
    </div>
  </div>
</body>
</html>
"""

PAGES = {
    "admin_login": LOGIN_HTML,
    "router": ROUTER_HTML,
    "wordpress": WP_HTML,
}


class HTTPHoneypot(Honeypot):
    """Honeypot web que sirve formularios de login falsos (admin, router, wordpress)."""

    def __init__(self, port: int = 8080, config: dict = None):
        super().__init__(name="http", port=port, config=config or {})
        self._thread: threading.Thread | None = None
        self._app: Flask | None = None

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def start(self):
        if self.running:
            return

        self._app = self._build_app()
        self.running = True

        self._thread = threading.Thread(
            target=self._run_flask, daemon=True
        )
        self._thread.start()

    def stop(self):
        self.running = False


    # ------------------------------------------------------------------
    # Flask app
    # ------------------------------------------------------------------

    def _build_app(self) -> Flask:
        app = Flask(__name__)
        app.secret_key = "easyhoneypot-secret"
        
        # Seleccionar template de HTML
        conf_page = self.config.get("fake_page", "admin_login")
        html_template = PAGES.get(conf_page, LOGIN_HTML)
        title = self.config.get("title", "Admin Panel")

        @app.route("/", methods=["GET", "POST"])
        @app.route("/login", methods=["POST"])
        @app.route("/wp-login.php", methods=["GET", "POST"])
        def catch_all():
            if request.method == "GET":
                return render_template_string(html_template, title=title)

            username = request.form.get("username", request.form.get("log", ""))
            password = request.form.get("password", request.form.get("pwd", ""))
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            user_agent = request.headers.get("User-Agent", "")

            # ── Disparar evento a los callbacks del core ──────────
            self.log_event(
                ip=ip,
                data={
                    "username": username,
                    "password": password,
                    "user_agent": user_agent,
                    "port": self.port,
                },
            )

            # Simular panel admin o falso 403
            return render_template_string(ADMIN_HTML, title=title)

        return app

    def _run_flask(self):
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
        self._app.run(host="0.0.0.0", port=self.port, use_reloader=False, threaded=True)
