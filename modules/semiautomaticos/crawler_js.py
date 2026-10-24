"""
Modulo semiautomatico: rastreo con navegador (crawler dinamico, Playwright).

A diferencia del crawler HTTP, este modulo EJECUTA JavaScript en un navegador
real (Chromium headless), por lo que puede auditar aplicaciones de una sola
pagina (SPA: React, Vue, Angular) cuyo contenido se genera en el cliente.

Descubre:
    - Rutas del lado cliente (navegando por los enlaces renderizados).
    - Formularios y campos que solo existen tras renderizar la pagina.
    - Endpoints de la API que la aplicacion consume (capturando las peticiones
      XHR/fetch que hace el navegador), que son la verdadera superficie de
      ataque de una SPA.

Todo lo descubierto se deposita en el contexto compartido para que los modulos
de inyeccion y autenticacion lo aprovechen.

Requiere Playwright y el navegador Chromium instalados:
    pip install playwright
    python -m playwright install chromium
Si no estan disponibles, el modulo se omite sin romper la auditoria (RNF-02).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo

# Cache del resultado de disponibilidad (evita reinicializar Playwright cada vez).
_DISPONIBLE: bool | None = None

# Extensiones de recursos o de codigo fuente (dev) que no son endpoints de API.
_EXT_ESTATICA = (".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                 ".ico", ".webp", ".woff", ".woff2", ".ttf", ".map",
                 ".ts", ".tsx", ".jsx", ".vue", ".scss", ".sass", ".less")
# Prefijos internos de herramientas de desarrollo (Vite, HMR, node_modules).
_PREFIJOS_DEV = ("/@", "/node_modules", "/__vite", "/src/", "/.vite")


@registrar_modulo
class CrawlerJS(ModuloBase):
    nombre = "crawler_js"
    categoria_default = CategoriaOWASP.RECONOCIMIENTO
    requiere_etiqueta = "Playwright/Chromium"

    @staticmethod
    def esta_disponible() -> bool:
        """Comprueba (una vez) si Playwright y Chromium estan instalados."""
        global _DISPONIBLE
        if _DISPONIBLE is not None:
            return _DISPONIBLE
        try:
            from playwright.sync_api import sync_playwright
            import os
            with sync_playwright() as p:
                ruta = p.chromium.executable_path
                _DISPONIBLE = bool(ruta and os.path.exists(ruta))
        except Exception:
            _DISPONIBLE = False
        return _DISPONIBLE

    def run(self):
        if not self.esta_disponible():
            self.logger.warning(
                "crawler_js: Playwright o Chromium no estan instalados; el modulo se "
                "omite. Instale con: pip install playwright && python -m playwright install chromium"
            )
            return []

        from playwright.sync_api import sync_playwright, Error as PlaywrightError

        opciones = self.config.get("opciones", {}).get("crawler_js", {})
        max_paginas = int(opciones.get("max_paginas", 15))
        espera_ms = int(opciones.get("espera_ms", 1500))
        timeout_ms = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 60)), 60) * 1000

        dominio = urlparse(self.objetivo).netloc
        visitadas: set[str] = set()
        por_visitar: list[str] = [self.objetivo]

        formularios: list[dict] = []
        urls_con_parametros: set[str] = set()
        endpoints_api: dict[str, str] = {}  # url -> metodo

        try:
            with sync_playwright() as p:
                navegador = p.chromium.launch(headless=True)
                # Escaneo autenticado: reutilizar el estado de sesion del login.
                auth = self.config.get("auth") or {}
                opciones_ctx = {"ignore_https_errors": True}
                if auth.get("storage_state"):
                    opciones_ctx["storage_state"] = auth["storage_state"]
                    self.logger.info("crawler_js: usando sesion autenticada del login.")
                contexto_nav = navegador.new_context(**opciones_ctx)
                if auth.get("headers"):
                    try:
                        contexto_nav.set_extra_http_headers(auth["headers"])
                    except Exception:
                        pass
                pagina = contexto_nav.new_page()

                # Capturar las peticiones de red (endpoints de la API).
                def on_request(req):
                    try:
                        # Solo llamadas a datos (XHR/fetch): son la API real de la app.
                        if req.resource_type not in ("xhr", "fetch"):
                            return
                        u = req.url.split("#", 1)[0]
                        ruta = urlparse(u).path.lower()
                        if ruta.endswith(_EXT_ESTATICA):
                            return
                        if any(ruta.startswith(p) for p in _PREFIJOS_DEV):
                            return
                        endpoints_api.setdefault(u, req.method)
                        if urlparse(u).netloc == dominio and urlparse(u).query:
                            urls_con_parametros.add(u)
                    except Exception:
                        pass

                pagina.on("request", on_request)

                while por_visitar and len(visitadas) < max_paginas:
                    url = por_visitar.pop(0)
                    if url in visitadas:
                        continue
                    visitadas.add(url)
                    try:
                        pagina.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                        try:
                            pagina.wait_for_load_state("networkidle", timeout=espera_ms + 3000)
                        except PlaywrightError:
                            pass
                        pagina.wait_for_timeout(espera_ms)
                    except PlaywrightError as exc:
                        self.logger.debug("crawler_js: no se pudo cargar %s: %s", url, exc)
                        continue

                    datos = self._extraer_dom(pagina)

                    for form in datos["formularios"]:
                        form["url_origen"] = url
                        form["action_absoluta"] = urljoin(url, form.get("action") or url)
                        formularios.append(form)

                    for href in datos["enlaces"]:
                        absoluta = urljoin(url, href).split("#", 1)[0]
                        partes = urlparse(absoluta)
                        if partes.netloc != dominio:
                            continue
                        if partes.query:
                            urls_con_parametros.add(absoluta)
                        if absoluta not in visitadas and absoluta not in por_visitar:
                            por_visitar.append(absoluta)

                navegador.close()
        except Exception as exc:
            self.logger.error("crawler_js: fallo el navegador headless: %s", exc)
            return []

        # Depositar en el contexto compartido.
        contexto = self.config.get("contexto")
        if contexto is not None:
            contexto["urls_con_parametros"].extend(
                u for u in urls_con_parametros if u not in contexto["urls_con_parametros"]
            )
            contexto["formularios"].extend(formularios)
            contexto["rutas_descubiertas"].extend(visitadas)
            contexto.setdefault("endpoints_api", [])
            for u, metodo in endpoints_api.items():
                contexto["endpoints_api"].append({"url": u, "metodo": metodo})

        self.logger.info(
            "crawler_js: %d pagina(s) renderizada(s), %d formulario(s), %d endpoint(s) de API.",
            len(visitadas), len(formularios), len(endpoints_api),
        )

        return self._construir_hallazgos(visitadas, formularios, urls_con_parametros, endpoints_api, dominio)

    def _extraer_dom(self, pagina) -> dict:
        """Extrae enlaces y formularios del DOM ya renderizado por JavaScript."""
        script = """() => {
            const enlaces = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
            const formularios = Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.getAttribute('action') || '',
                method: (f.getAttribute('method') || 'get').toLowerCase(),
                campos: Array.from(f.querySelectorAll('input,textarea,select'))
                    .filter(i => i.name)
                    .map(i => ({ nombre: i.name, tipo: i.getAttribute('type') || 'text' }))
            }));
            return { enlaces, formularios };
        }"""
        try:
            return pagina.evaluate(script)
        except Exception:
            return {"enlaces": [], "formularios": []}

    def _construir_hallazgos(self, visitadas, formularios, urls_param, endpoints_api, dominio):
        hallazgos = []
        hallazgos.append(self.crear_hallazgo(
            titulo="Superficie de ataque descubierta (con JavaScript)",
            severidad=Severidad.INFORMATIVA,
            evidencia=(
                f"Se renderizaron {len(visitadas)} pagina(s) ejecutando JavaScript. "
                f"Se hallaron {len(formularios)} formulario(s), {len(urls_param)} URL(s) "
                f"con parametros y {len(endpoints_api)} endpoint(s) de API, que alimentan "
                f"a los modulos de inyeccion y autenticacion."
            ),
            recomendacion=(
                "Verifique que cada endpoint y formulario aplique autenticacion, control "
                "de acceso y validacion de entrada del lado del servidor."
            ),
            ubicacion=self.objetivo,
        ))

        if endpoints_api:
            internos = {u: m for u, m in endpoints_api.items() if urlparse(u).netloc == dominio}
            externos = {u: m for u, m in endpoints_api.items() if urlparse(u).netloc != dominio}
            muestra_int = [f"{m} {u}" for u, m in list(internos.items())[:15]]
            evidencia = "Endpoints de API detectados en el trafico de la aplicacion. "
            if muestra_int:
                evidencia += "Mismo dominio: " + "; ".join(muestra_int) + ". "
            if externos:
                evidencia += "Otros origenes (posible API backend): " + \
                             ", ".join(sorted(set(externos))[:8]) + "."
            hallazgos.append(self.crear_hallazgo(
                titulo=f"Endpoints de API descubiertos ({len(endpoints_api)})",
                severidad=Severidad.INFORMATIVA,
                evidencia=evidencia,
                recomendacion=(
                    "Dirija tambien la auditoria a estos endpoints de la API, que son la "
                    "superficie real de la aplicacion. Confirme que exigen autenticacion "
                    "y aplican control de acceso por objeto (evitar IDOR)."
                ),
                ubicacion=self.objetivo,
            ))

        for form in formularios:
            campos = ", ".join(c["nombre"] for c in form["campos"]) or "(sin campos)"
            hallazgos.append(self.crear_hallazgo(
                titulo="Formulario detectado (renderizado por JS)",
                severidad=Severidad.INFORMATIVA,
                evidencia=(
                    f"Formulario {form['method'].upper()} hacia {form['action_absoluta']} "
                    f"con campos: {campos}."
                ),
                recomendacion="Valide y sanee en el servidor todas las entradas de este formulario.",
                ubicacion=form["action_absoluta"],
            ))

        return hallazgos
