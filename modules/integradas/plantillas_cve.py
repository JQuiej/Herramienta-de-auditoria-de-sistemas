"""
Modulo de herramienta integrada: deteccion por plantillas de CVE con nuclei.

Cubre:
    Deteccion de componentes con CVE conocidos, misconfiguraciones.
    Categoria OWASP: A06 - Vulnerable Components / A05 - Security Misconfiguration.

Envuelve nuclei con configuracion conservadora (documento seccion 11.6.3):
    - Plantillas no intrusivas, con rate limiting para no sobrecargar el objetivo.
    - Salida JSONL parseada al modelo de datos comun (Hallazgo).
"""

from __future__ import annotations

import json

from core.models import CategoriaOWASP, Severidad
from modules.integradas.base_herramienta import HerramientaExterna
from core.registry import registrar_modulo


# Mapeo de la severidad de nuclei a la severidad interna.
SEVERIDAD_NUCLEI = {
    "critical": Severidad.CRITICA,
    "high": Severidad.ALTA,
    "medium": Severidad.MEDIA,
    "low": Severidad.BAJA,
    "info": Severidad.INFORMATIVA,
    "unknown": Severidad.INFORMATIVA,
}


@registrar_modulo
class PlantillasCVE(HerramientaExterna):
    nombre = "plantillas_cve"
    categoria_default = CategoriaOWASP.VULNERABLE_COMPONENTS
    binarios = ["nuclei"]

    def run(self):
        binario = self.localizar_binario()
        if not binario:
            return self._binario_ausente()

        opciones = self.config.get("opciones", {}).get("plantillas_cve", {})
        rate = str(opciones.get("rate_limit", 50))
        severidades = opciones.get("severidades", "critical,high,medium,low")

        # Comando conservador: JSONL, rate limiting, sin actualizacion interactiva,
        # severidades acotadas y sin interaccion.
        comando = [
            binario, "-u", self.objetivo, "-jsonl", "-silent",
            "-rate-limit", rate, "-severity", severidades,
            "-disable-update-check", "-no-color",
        ]
        resultado = self.ejecutar_comando(comando, self.timeout())
        if resultado is None:
            return []

        return self._parsear_jsonl(resultado.stdout or "")

    def _parsear_jsonl(self, salida: str):
        """Traduce la salida JSONL de nuclei a hallazgos."""
        hallazgos = []
        for linea in salida.splitlines():
            linea = linea.strip()
            if not linea:
                continue
            try:
                item = json.loads(linea)
            except json.JSONDecodeError:
                continue

            info = item.get("info", {})
            sev_txt = (info.get("severity") or "info").lower()
            severidad = SEVERIDAD_NUCLEI.get(sev_txt, Severidad.INFORMATIVA)
            nombre_plantilla = info.get("name") or item.get("template-id", "hallazgo nuclei")
            matched = item.get("matched-at") or item.get("host") or self.objetivo

            # Clasificar por categoria: si la plantilla es un CVE -> componentes.
            template_id = item.get("template-id", "")
            categoria = (
                CategoriaOWASP.VULNERABLE_COMPONENTS
                if template_id.lower().startswith("cve")
                else CategoriaOWASP.SECURITY_MISCONFIG
            )

            descripcion = info.get("description", "").strip()
            referencias = info.get("reference") or []
            ref_txt = f" Referencias: {', '.join(referencias)}." if referencias else ""

            hallazgos.append(self.crear_hallazgo(
                titulo=f"nuclei: {nombre_plantilla}",
                severidad=severidad,
                categoria=categoria,
                evidencia=(
                    f"La plantilla '{template_id}' coincidio en {matched}. "
                    f"{descripcion}{ref_txt}"
                ).strip(),
                recomendacion=(
                    "Revise y remedie la vulnerabilidad reportada por nuclei; actualice el "
                    "componente afectado o aplique la mitigacion indicada en las referencias."
                ),
                ubicacion=str(matched),
            ))

        self.logger.info("plantillas_cve: nuclei reporto %d coincidencia(s).", len(hallazgos))
        return hallazgos
