"""
Modulo de herramienta integrada: deteccion de inyeccion SQL con sqlmap.

Cubre:
    RF-09   Detectar inyeccion SQL en parametros con entrada de usuario.
    Categoria OWASP: A03 - Injection.

Envuelve sqlmap con una configuracion DELIBERADAMENTE CONSERVADORA (documento
secciones 11.6.3 y 11.6.5), priorizando la DETECCION sobre la explotacion:
    - --batch: sin interaccion.
    - --level 1 --risk 1: pruebas de menor intensidad.
    - NO se usan --dump, --os-shell ni ninguna opcion de post-explotacion o
      extraccion masiva de datos (queda fuera de alcance).

Las URLs con parametros a evaluar provienen del contexto que dejo el crawler,
o de 'opciones.inyeccion_sql.urls' en la configuracion.
"""

from __future__ import annotations

import re

from core.models import CategoriaOWASP, Severidad
from modules.integradas.base_herramienta import HerramientaExterna
from core.registry import registrar_modulo


@registrar_modulo
class InyeccionSQL(HerramientaExterna):
    nombre = "inyeccion_sql"
    categoria_default = CategoriaOWASP.INJECTION
    binarios = ["sqlmap"]

    def run(self):
        binario = self.localizar_binario()
        if not binario:
            return self._binario_ausente()

        objetivos = self._objetivos()
        if not objetivos:
            self.logger.info(
                "inyeccion_sql: no hay URLs con parametros para evaluar. Ejecute el "
                "crawler antes, o indique 'opciones.inyeccion_sql.urls'."
            )
            return []

        hallazgos = []
        max_urls = int(self.config.get("opciones", {}).get("inyeccion_sql", {}).get("max_urls", 5))
        for url in objetivos[:max_urls]:
            hallazgos += self._evaluar_url(binario, url)
        return hallazgos

    def _objetivos(self) -> list[str]:
        """URLs con parametros: del contexto (crawler) o de la configuracion."""
        opciones = self.config.get("opciones", {}).get("inyeccion_sql", {})
        urls = list(opciones.get("urls", []))
        urls += self.contexto().get("urls_con_parametros", [])
        # Sin duplicados, conservando el orden.
        vistos, unicos = set(), []
        for u in urls:
            if u not in vistos:
                vistos.add(u)
                unicos.append(u)
        return unicos

    def _evaluar_url(self, binario: str, url: str):
        # Comando conservador: solo deteccion, sin extraccion de datos.
        comando = [
            binario, "-u", url, "--batch", "--level", "1", "--risk", "1",
            "--smart", "--technique", "BEUST", "--flush-session",
            "--timeout", "10", "--retries", "1", "--disable-coloring",
        ]
        resultado = self.ejecutar_comando(comando, self.timeout())
        if resultado is None:
            return []

        salida = (resultado.stdout or "") + (resultado.stderr or "")
        return self._parsear_salida(salida, url)

    def _parsear_salida(self, salida: str, url: str):
        hallazgos = []
        vulnerable = (
            "is vulnerable" in salida.lower()
            or "sqlmap identified the following injection point" in salida.lower()
        )
        if not vulnerable:
            self.logger.info("inyeccion_sql: %s no resulto vulnerable.", url)
            return hallazgos

        # Extraer los parametros vulnerables mencionados.
        params = set()
        for m in re.finditer(r"Parameter:\s*([^\s(]+)", salida):
            params.add(m.group(1))
        for m in re.finditer(r"parameter '([^']+)' is vulnerable", salida, re.IGNORECASE):
            params.add(m.group(1))
        detalle = f" Parametro(s) afectado(s): {', '.join(sorted(params))}." if params else ""

        hallazgos.append(self.crear_hallazgo(
            titulo="Inyeccion SQL confirmada",
            severidad=Severidad.CRITICA,
            evidencia=(
                f"sqlmap confirmo que {url} es vulnerable a inyeccion SQL.{detalle} "
                "La deteccion se realizo en modo conservador, sin extraccion de datos."
            ),
            recomendacion=(
                "Use consultas parametrizadas (prepared statements) y valide/escape toda "
                "entrada del usuario. Aplique el principio de menor privilegio en la cuenta "
                "de base de datos que utiliza la aplicacion."
            ),
            ubicacion=url,
        ))
        self.logger.info("inyeccion_sql: VULNERABLE -> %s", url)
        return hallazgos
