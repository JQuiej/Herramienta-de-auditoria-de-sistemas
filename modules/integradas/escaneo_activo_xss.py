"""
Modulo de herramienta integrada: escaneo activo de XSS con dalfox.

Cubre:
    RF-09   Detectar Cross-Site Scripting (XSS) en parametros con entrada de usuario.
    Categoria OWASP: A03 - Injection.

Envuelve dalfox con configuracion conservadora (documento seccion 11.6.3):
    - Modo de deteccion, sin explotacion agresiva.
    - Salida JSONL parseada al modelo de datos comun (Hallazgo).

Las URLs con parametros provienen del contexto que dejo el crawler, o de
'opciones.escaneo_activo_xss.urls' en la configuracion.
"""

from __future__ import annotations

import json

from core.models import CategoriaOWASP, Severidad
from modules.integradas.base_herramienta import HerramientaExterna
from core.registry import registrar_modulo


@registrar_modulo
class EscaneoActivoXSS(HerramientaExterna):
    nombre = "escaneo_activo_xss"
    categoria_default = CategoriaOWASP.INJECTION
    binarios = ["dalfox"]

    def run(self):
        binario = self.localizar_binario()
        if not binario:
            return self._binario_ausente()

        objetivos = self._objetivos()
        if not objetivos:
            self.logger.info(
                "escaneo_activo_xss: no hay URLs con parametros para evaluar. Ejecute el "
                "crawler antes, o indique 'opciones.escaneo_activo_xss.urls'."
            )
            return []

        hallazgos = []
        max_urls = int(self.config.get("opciones", {}).get("escaneo_activo_xss", {}).get("max_urls", 5))
        for url in objetivos[:max_urls]:
            hallazgos += self._evaluar_url(binario, url)
        return hallazgos

    def _objetivos(self) -> list[str]:
        opciones = self.config.get("opciones", {}).get("escaneo_activo_xss", {})
        urls = list(opciones.get("urls", []))
        urls += self.contexto().get("urls_con_parametros", [])
        vistos, unicos = set(), []
        for u in urls:
            if u not in vistos:
                vistos.add(u)
                unicos.append(u)
        return unicos

    def _evaluar_url(self, binario: str, url: str):
        # Comando conservador: escaneo de una URL, salida JSON, sin ruido.
        comando = [
            binario, "url", url, "--format", "json", "--silence",
            "--no-color", "--skip-bav",
        ]
        resultado = self.ejecutar_comando(comando, self.timeout())
        if resultado is None:
            return []

        return self._parsear_salida(resultado.stdout or "", url)

    def _parsear_salida(self, salida: str, url: str):
        hallazgos = []
        # dalfox emite un JSON (array o lineas) con los POC encontrados.
        items = []
        salida = salida.strip()
        if not salida:
            self.logger.info("escaneo_activo_xss: %s sin hallazgos de XSS.", url)
            return hallazgos
        try:
            data = json.loads(salida)
            items = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Puede venir en JSONL: una linea por hallazgo.
            for linea in salida.splitlines():
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    items.append(json.loads(linea))
                except json.JSONDecodeError:
                    continue

        for item in items:
            if not isinstance(item, dict):
                continue
            tipo = item.get("type", "")
            # Solo reportar verificaciones reales (POC), no mensajes informativos.
            if tipo and tipo.upper() not in ("V", "VERIFY", "POC", "G", "GREP"):
                continue
            param = item.get("param", "")
            payload = item.get("data") or item.get("payload") or ""
            metodo = item.get("method", "GET")
            hallazgos.append(self.crear_hallazgo(
                titulo="Cross-Site Scripting (XSS) confirmado",
                severidad=Severidad.ALTA,
                evidencia=(
                    f"dalfox confirmo XSS en {url} (metodo {metodo}"
                    f"{', parametro ' + param if param else ''}). "
                    f"Payload: {payload[:200]}"
                ),
                recomendacion=(
                    "Codifique (escape) toda salida segun su contexto (HTML, atributo, JS) y "
                    "valide la entrada del usuario. Aplique una Content-Security-Policy "
                    "restrictiva como defensa en profundidad."
                ),
                ubicacion=url,
            ))

        if hallazgos:
            self.logger.info("escaneo_activo_xss: %d XSS confirmado(s) en %s.", len(hallazgos), url)
        return hallazgos
