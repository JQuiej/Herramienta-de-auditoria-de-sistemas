"""
Autenticador: inicia sesion una vez y prepara el estado para reutilizarlo.

Permite el "escaneo autenticado": la herramienta hace login en el objetivo y
comparte la sesion resultante (cookies, token de tipo Bearer y estado de
almacenamiento del navegador) con todos los modulos, de modo que el crawler y
los modulos de deteccion trabajen DETRAS del login, sobre las areas privadas de
la aplicacion.

Dos modos:
    - browser: usa un navegador real (Playwright). Es el adecuado para SPAs, que
      guardan el token en localStorage y lo envian por la cabecera Authorization.
      Devuelve tambien el "storage_state" para que el crawler_js arranque ya
      autenticado.
    - http: envia las credenciales por HTTP (requests) y captura las cookies de
      sesion. Sirve para formularios clasicos del lado servidor.

Nunca almacena las credenciales: se usan solo para la peticion de login.
"""

from __future__ import annotations

from urllib.parse import urlparse


def _playwright_disponible() -> bool:
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        import os
        with sync_playwright() as p:
            ruta = p.chromium.executable_path
            return bool(ruta and os.path.exists(ruta))
    except Exception:
        return False


def autenticar(login: dict, logger) -> dict:
    """
    Ejecuta el login segun la configuracion y devuelve el estado de sesion:
        {
          "exito": bool,
          "cookies": {nombre: valor},          # para modulos basados en requests
          "headers": {"Authorization": "..."}, # token Bearer, si se detecta
          "storage_state": {...} | None,       # para el navegador (crawler_js)
          "evidencia": str,
        }
    """
    vacio = {"exito": False, "cookies": {}, "headers": {}, "storage_state": None, "evidencia": ""}
    url = login.get("url")
    usuario = login.get("usuario")
    password = login.get("password")
    if not (url and usuario and password):
        vacio["evidencia"] = "Login incompleto: se requieren url, usuario y contrasena."
        return vacio

    modo = login.get("modo", "auto")
    if modo == "auto":
        modo = "browser" if _playwright_disponible() else "http"

    if modo == "browser":
        return _login_browser(login, logger)
    return _login_http(login, logger)


def _login_browser(login: dict, logger) -> dict:
    resultado = {"exito": False, "cookies": {}, "headers": {}, "storage_state": None, "evidencia": ""}
    try:
        from playwright.sync_api import sync_playwright, Error as PlaywrightError
    except ImportError:
        resultado["evidencia"] = "Playwright no esta instalado para el login por navegador."
        return resultado

    url = login["url"]
    usuario, password = login["usuario"], login["password"]
    campo_u = login.get("campo_usuario", "username")
    campo_p = login.get("campo_password", "password")
    espera_ms = int(login.get("espera_ms", 2000))

    auth_headers: dict[str, str] = {}

    try:
        with sync_playwright() as p:
            nav = p.chromium.launch(headless=True)
            ctx = nav.new_context(ignore_https_errors=True)
            pagina = ctx.new_page()

            # Capturar la cabecera Authorization que la app use tras el login.
            def on_request(req):
                try:
                    for k, v in req.headers.items():
                        if k.lower() == "authorization" and v:
                            auth_headers["Authorization"] = v
                except Exception:
                    pass
            pagina.on("request", on_request)

            pagina.goto(url, wait_until="domcontentloaded", timeout=30000)
            pagina.wait_for_timeout(1000)

            if not _rellenar_login(pagina, campo_u, campo_p, usuario, password, logger):
                resultado["evidencia"] = "No se encontraron los campos de usuario/contrasena en la pagina de login."
                nav.close()
                return resultado

            # Enviar el formulario y esperar la respuesta.
            _enviar_login(pagina)
            try:
                pagina.wait_for_load_state("networkidle", timeout=espera_ms + 4000)
            except PlaywrightError:
                pass
            pagina.wait_for_timeout(espera_ms)

            # Recolectar estado de sesion.
            cookies_lista = ctx.cookies()
            cookies = {c["name"]: c["value"] for c in cookies_lista}
            storage_state = ctx.storage_state()
            token_storage = _buscar_token_storage(pagina)

            nav.close()
    except Exception as exc:
        resultado["evidencia"] = f"Fallo el login por navegador: {exc}"
        return resultado

    headers = dict(auth_headers)
    if not headers.get("Authorization") and token_storage:
        headers["Authorization"] = f"Bearer {token_storage}"

    # Consideramos exito si se obtuvo una cookie de sesion o un token.
    exito = bool(cookies) or bool(headers.get("Authorization"))
    resultado.update({
        "exito": exito,
        "cookies": cookies,
        "headers": headers,
        "storage_state": storage_state,
        "evidencia": (
            f"Login por navegador {'exitoso' if exito else 'sin sesion detectada'}: "
            f"{len(cookies)} cookie(s)"
            + (", token Authorization capturado" if headers.get("Authorization") else "")
            + "."
        ),
    })
    if logger:
        logger.info("autenticador: %s", resultado["evidencia"])
    return resultado


def _rellenar_login(pagina, campo_u, campo_p, usuario, password, logger) -> bool:
    """Rellena los campos de usuario y contrasena con varias heuristicas."""
    sel_usuario = [
        f"input[name='{campo_u}']", f"input[id='{campo_u}']",
        "input[type='email']", "input[name*='user' i]", "input[name*='correo' i]",
        "input[type='text']",
    ]
    sel_password = [
        f"input[name='{campo_p}']", f"input[id='{campo_p}']", "input[type='password']",
    ]
    ok_u = _rellenar_primero(pagina, sel_usuario, usuario)
    ok_p = _rellenar_primero(pagina, sel_password, password)
    return ok_u and ok_p


def _rellenar_primero(pagina, selectores, valor) -> bool:
    for sel in selectores:
        try:
            el = pagina.query_selector(sel)
            if el:
                el.fill(valor)
                return True
        except Exception:
            continue
    return False


def _enviar_login(pagina) -> None:
    for sel in ["button[type='submit']", "input[type='submit']",
                "button:has-text('Ingresar')", "button:has-text('Entrar')",
                "button:has-text('Iniciar')", "button:has-text('Login')"]:
        try:
            el = pagina.query_selector(sel)
            if el:
                el.click()
                return
        except Exception:
            continue
    # Si no hay boton claro, enviar con Enter desde el campo de contrasena.
    try:
        pagina.press("input[type='password']", "Enter")
    except Exception:
        pass


def _buscar_token_storage(pagina) -> str | None:
    """Busca un token (JWT) en localStorage/sessionStorage."""
    script = """() => {
        const claves = ['token','access_token','accessToken','jwt','authToken','id_token'];
        const buscar = (s) => {
            for (let i = 0; i < s.length; i++) {
                const k = s.key(i);
                if (claves.some(c => k.toLowerCase().includes(c.toLowerCase()))) {
                    const v = s.getItem(k);
                    if (v && v.length > 10) return v.replace(/^\"|\"$/g, '');
                }
            }
            return null;
        };
        return buscar(window.localStorage) || buscar(window.sessionStorage);
    }"""
    try:
        return pagina.evaluate(script)
    except Exception:
        return None


def _login_http(login: dict, logger) -> dict:
    """Login clasico por formulario HTTP: POST de credenciales y captura de cookies."""
    import requests
    resultado = {"exito": False, "cookies": {}, "headers": {}, "storage_state": None, "evidencia": ""}
    url = login["url"]
    datos = {
        login.get("campo_usuario", "username"): login["usuario"],
        login.get("campo_password", "password"): login["password"],
    }
    try:
        sesion = requests.Session()
        resp = sesion.post(url, data=datos, timeout=20, allow_redirects=True)
    except requests.RequestException as exc:
        resultado["evidencia"] = f"Fallo el login HTTP: {exc}"
        return resultado

    cookies = sesion.cookies.get_dict()
    exito = bool(cookies) and resp.status_code < 400
    resultado.update({
        "exito": exito,
        "cookies": cookies,
        "evidencia": (
            f"Login HTTP: HTTP {resp.status_code}, {len(cookies)} cookie(s) de sesion."
        ),
    })
    if logger:
        logger.info("autenticador: %s", resultado["evidencia"])
    return resultado
