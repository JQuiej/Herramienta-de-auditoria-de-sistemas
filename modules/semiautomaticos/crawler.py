"""
Modulo semiautomatico: rastreo (crawler) del objetivo.

Cubre:
    Reconocimiento (documento seccion 11.5.3): base para los modulos de inyeccion.
    Descubre rutas, formularios y parametros que no son evidentes a primera
    vista y ALIMENTA automaticamente el contexto compartido con las URLs que
    tienen parametros de entrada y los formularios encontrados, de modo que los
    modulos de inyeccion (fases siguientes) los consuman.

Es "semiautomatico": combina logica propia (parseo de enlaces y formularios)
con reconocimiento activo limitado. Se mantiene dentro del mismo dominio y
respeta un limite de paginas para no sobrecargar el objetivo (uso responsable).
"""

from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

# Patrones para descubrir endpoints referenciados en el codigo (util en SPAs,
# donde las rutas y llamadas a la API viven en JavaScript, no en el HTML).
_RE_RUTA = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,80})["'`]""")
_RE_URL_ABS = re.compile(r"""(https?://[^\s"'`<>]{5,120})""")

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


class _ParserHTML(HTMLParser):
    """Extrae enlaces (<a href>), formularios (<form>, <input>) y senales de SPA."""

    def __init__(self):
        super().__init__()
        self.enlaces: list[str] = []
        self.formularios: list[dict] = []
        self.scripts_src: list[str] = []
        self.tiene_raiz_spa: bool = False
        self._form_actual: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        # Senal de aplicacion de una sola pagina (SPA): un contenedor vacio que
        # JavaScript rellena en el navegador (React/Vue/Angular usan id root/app).
        if tag in ("div", "main") and d.get("id", "").lower() in ("root", "app", "__next", "__nuxt"):
            self.tiene_raiz_spa = True
        if tag == "script" and d.get("src"):
            self.scripts_src.append(d["src"])
        if tag == "a" and d.get("href"):
            self.enlaces.append(d["href"])
        elif tag == "form":
            self._form_actual = {
                "action": d.get("action", ""),
                "method": (d.get("method") or "get").lower(),
                "campos": [],
            }
        elif tag in ("input", "textarea", "select") and self._form_actual is not None:
            nombre = d.get("name")
            if nombre:
                self._form_actual["campos"].append({
                    "nombre": nombre,
                    "tipo": d.get("type", "text"),
                })

    def handle_endtag(self, tag):
        if tag == "form" and self._form_actual is not None:
            self.formularios.append(self._form_actual)
            self._form_actual = None


@registrar_modulo
class Crawler(ModuloBase):
    nombre = "crawler"
    categoria_default = CategoriaOWASP.RECONOCIMIENTO

    def run(self):
        hallazgos = []
        opciones = self.config.get("opciones", {}).get("crawler", {})
        max_paginas = int(opciones.get("max_paginas", 25))
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        dominio = urlparse(self.objetivo).netloc
        visitadas: set[str] = set()
        cola: deque[str] = deque([self.objetivo])

        urls_con_parametros: list[str] = []
        formularios: list[dict] = []
        endpoints_internos: set[str] = set()   # rutas del mismo dominio halladas en el codigo
        endpoints_externos: set[str] = set()   # URLs absolutas a otros origenes (posible API)
        spa_detectada = False

        self.emitir(f"iniciando rastreo de {self.objetivo} (hasta {max_paginas} paginas)")
        while cola and len(visitadas) < max_paginas:
            url = cola.popleft()
            if url in visitadas:
                continue
            visitadas.add(url)

            try:
                resp = self.http.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException as exc:
                self.logger.debug("crawler: fallo al solicitar %s: %s", url, exc)
                self.emitir(f"x sin respuesta: {url}")
                continue
            self.emitir(f"GET {url} -> HTTP {resp.status_code}")

            content_type = resp.headers.get("Content-Type", "")
            cuerpo = resp.text
            # Parsear si el Content-Type es HTML o, si falta, si el cuerpo lo parece.
            parece_html = "<html" in cuerpo[:1024].lower() or "<form" in cuerpo[:1024].lower()
            if "text/html" not in content_type and not parece_html:
                continue

            parser = _ParserHTML()
            try:
                parser.feed(cuerpo)
            except Exception as exc:
                self.logger.debug("crawler: error al parsear %s: %s", url, exc)
                continue

            # Registrar formularios.
            for form in parser.formularios:
                form["url_origen"] = url
                form["action_absoluta"] = urljoin(url, form["action"] or url)
                formularios.append(form)
                campos = ", ".join(c.get("nombre", "") for c in form.get("campos", [])) or "(sin campos)"
                self.emitir(f"  + formulario {form['method'].upper()} {form['action_absoluta']} [{campos}]")

            # Procesar enlaces: encolar los del mismo dominio y detectar parametros.
            for href in parser.enlaces:
                absoluta = urljoin(url, href)
                partes = urlparse(absoluta)
                if partes.netloc != dominio:
                    continue
                limpia = absoluta.split("#", 1)[0]
                if partes.query:
                    if limpia not in urls_con_parametros:
                        urls_con_parametros.append(limpia)
                        self.emitir(f"  + endpoint con parametros: {limpia}")
                if limpia not in visitadas and limpia not in cola:
                    cola.append(limpia)
                    self.emitir(f"  -> en cola: {limpia}")

            # Detectar SPA (contenido dibujado por JavaScript) en la pagina raiz.
            if url == self.objetivo and parser.tiene_raiz_spa and not parser.formularios \
                    and not parser.enlaces:
                spa_detectada = True

            # Descubrir endpoints referenciados en el codigo (rutas y llamadas a la
            # API viven en JS en las SPAs). Se filtran recursos estaticos.
            for ruta in _RE_RUTA.findall(cuerpo):
                if self._es_recurso_estatico(ruta):
                    continue
                full = urljoin(self.objetivo, ruta).split("#", 1)[0]
                if full not in endpoints_internos:
                    endpoints_internos.add(full)
                    self.emitir(f"  . ruta en codigo: {full}")
            for absoluta in _RE_URL_ABS.findall(cuerpo):
                if urlparse(absoluta).netloc != dominio and not self._es_recurso_estatico(absoluta):
                    endpoints_externos.add(absoluta)

        # --- Depositar hallazgos de reconocimiento en el contexto compartido ---
        contexto = self.config.get("contexto")
        if contexto is not None:
            contexto["urls_con_parametros"].extend(
                u for u in urls_con_parametros if u not in contexto["urls_con_parametros"]
            )
            contexto["formularios"].extend(formularios)
            contexto["rutas_descubiertas"].extend(visitadas)

        self.logger.info(
            "crawler: %d paginas visitadas, %d URLs con parametros, %d formularios.",
            len(visitadas), len(urls_con_parametros), len(formularios),
        )

        # --- Generar hallazgos informativos ---
        hallazgos.append(self.crear_hallazgo(
            titulo="Superficie de ataque descubierta",
            severidad=Severidad.INFORMATIVA,
            evidencia=(
                f"Se rastrearon {len(visitadas)} paginas del dominio {dominio}: "
                f"{len(urls_con_parametros)} URL(s) con parametros y "
                f"{len(formularios)} formulario(s) que serviran de entrada a los "
                f"modulos de inyeccion."
            ),
            recomendacion=(
                "Revise que las rutas y parametros expuestos sean los previstos y que "
                "ninguna funcionalidad sensible sea accesible sin autenticacion."
            ),
            ubicacion=self.objetivo,
        ))

        # Aviso de SPA: el contenido se dibuja con JavaScript y este rastreador no
        # lo ejecuta, por lo que la superficie real (rutas, formularios, campos) no
        # aparece. La auditoria de aplicacion debe dirigirse a la API/backend.
        if spa_detectada and not formularios and not urls_con_parametros:
            pistas = ""
            if endpoints_externos:
                pistas = (" Posibles URLs de la API detectadas en el codigo: "
                          + ", ".join(sorted(endpoints_externos)[:8]) + ".")
            hallazgos.append(self.crear_hallazgo(
                titulo="El objetivo es una aplicacion de una sola pagina (SPA)",
                severidad=Severidad.INFORMATIVA,
                evidencia=(
                    "El objetivo entrega un HTML minimo cuyo contenido lo genera "
                    "JavaScript en el navegador (React/Vue/Angular). Este rastreador "
                    "no ejecuta JavaScript, por lo que no puede ver las rutas, "
                    "formularios ni parametros de la aplicacion. Los modulos de "
                    "inyeccion y autenticacion no tienen entradas que evaluar." + pistas
                ),
                recomendacion=(
                    "Para auditar la logica de la aplicacion, dirija el escaneo a la "
                    "API/backend que consume esta SPA (normalmente en otra URL o puerto), "
                    "no al servidor de archivos del frontend. Puede indicar manualmente "
                    "los endpoints con parametros y la URL de login en las opciones."
                ),
                ubicacion=self.objetivo,
            ))

        # Endpoints internos descubiertos en el codigo (rutas candidatas).
        if endpoints_internos:
            muestra = sorted(endpoints_internos)[:15]
            hallazgos.append(self.crear_hallazgo(
                titulo=f"Rutas/endpoints referenciados en el codigo ({len(endpoints_internos)})",
                severidad=Severidad.INFORMATIVA,
                evidencia="Rutas encontradas en el HTML/JavaScript del objetivo: " + ", ".join(muestra),
                recomendacion=(
                    "Verifique que estas rutas apliquen control de acceso y validacion "
                    "de entrada; considere auditarlas directamente contra el backend."
                ),
                ubicacion=self.objetivo,
            ))

        for form in formularios:
            campos = ", ".join(c["nombre"] for c in form["campos"]) or "(sin campos)"
            hallazgos.append(self.crear_hallazgo(
                titulo="Formulario detectado",
                severidad=Severidad.INFORMATIVA,
                evidencia=(
                    f"Formulario {form['method'].upper()} hacia "
                    f"{form['action_absoluta']} con campos: {campos}."
                ),
                recomendacion=(
                    "Valide y sanee en el servidor todas las entradas de este "
                    "formulario para prevenir inyeccion y XSS."
                ),
                ubicacion=form["action_absoluta"],
            ))

        return hallazgos

    @staticmethod
    def _es_recurso_estatico(ruta: str) -> bool:
        """Descarta rutas a recursos estaticos (no son endpoints de la aplicacion)."""
        r = ruta.lower().split("?", 1)[0]
        extensiones = (
            ".js", ".mjs", ".ts", ".jsx", ".tsx", ".css", ".map", ".png", ".jpg",
            ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf",
            ".eot", ".mp4", ".webm", ".json", ".txt", ".xml",
        )
        if r.endswith(extensiones):
            return True
        # Rutas internas de herramientas de desarrollo (Vite, HMR, node_modules).
        prefijos_dev = ("/@", "/node_modules", "/__vite", "/src/", "/assets/")
        return any(r.startswith(p) for p in prefijos_dev)
