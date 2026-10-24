"""
Motor de analisis de riesgos (documento seccion 11.6.4).

El motor NO detecta nada por si mismo: procesa la lista de hallazgos ya
generados por los modulos y, para cada uno:
    - Deriva un IMPACTO (1-5) a partir de su categoria OWASP.
    - Deriva una PROBABILIDAD de explotacion (1-5) a partir de su severidad.
    - Calcula el nivel de riesgo con la formula Riesgo = Probabilidad x Impacto
      y lo clasifica segun la escala de la seccion 5.3 del documento.
    - Estima una puntuacion CVSS a partir de la severidad si el modulo no la
      proporciono (documento seccion 11.5.4).

De este modo los hallazgos tecnicos quedan ubicados en la MISMA matriz de
riesgo (probabilidad x impacto) que los riesgos documentados en la seccion 7,
haciendolos directamente comparables.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.models import CategoriaOWASP, Hallazgo, Severidad


# Impacto (1-5) segun la categoria OWASP del hallazgo (seccion 5.2).
IMPACTO_POR_CATEGORIA: dict[CategoriaOWASP, int] = {
    CategoriaOWASP.INJECTION: 5,
    CategoriaOWASP.AUTH_FAILURES: 5,
    CategoriaOWASP.BROKEN_ACCESS: 5,
    CategoriaOWASP.SSRF: 4,
    CategoriaOWASP.CRYPTO_FAILURES: 4,
    CategoriaOWASP.VULNERABLE_COMPONENTS: 4,
    CategoriaOWASP.SUPPLY_CHAIN: 4,
    CategoriaOWASP.INSECURE_DESIGN: 4,
    CategoriaOWASP.INTEGRITY_FAILURES: 4,
    CategoriaOWASP.SECURITY_MISCONFIG: 3,
    CategoriaOWASP.LOGGING_FAILURES: 2,
    CategoriaOWASP.RECONOCIMIENTO: 1,
}

# Probabilidad (1-5) de explotacion segun la severidad (seccion 5.1).
PROBABILIDAD_POR_SEVERIDAD: dict[Severidad, int] = {
    Severidad.CRITICA: 5,
    Severidad.ALTA: 4,
    Severidad.MEDIA: 3,
    Severidad.BAJA: 2,
    Severidad.INFORMATIVA: 1,
}

# CVSS estimado (0.0-10.0) segun la severidad, si el modulo no lo provee.
CVSS_POR_SEVERIDAD: dict[Severidad, float] = {
    Severidad.CRITICA: 9.5,
    Severidad.ALTA: 7.5,
    Severidad.MEDIA: 5.0,
    Severidad.BAJA: 3.0,
    Severidad.INFORMATIVA: 0.0,
}


def nivel_riesgo(valor: int) -> str:
    """Clasifica el valor de riesgo (1-25) segun la escala de la seccion 5.3."""
    if valor <= 5:
        return "Bajo"
    if valor <= 10:
        return "Medio"
    if valor <= 15:
        return "Alto"
    return "Critico"


@dataclass
class ResumenRiesgo:
    """Resultado agregado del analisis de riesgos sobre todos los hallazgos."""

    total: int = 0
    por_nivel: dict[str, int] = field(default_factory=dict)
    por_severidad: dict[str, int] = field(default_factory=dict)
    por_categoria: dict[str, int] = field(default_factory=dict)
    # Mapa de calor: matriz[probabilidad][impacto] = numero de hallazgos.
    mapa_calor: dict[int, dict[int, int]] = field(default_factory=dict)
    riesgo_promedio: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "por_nivel": self.por_nivel,
            "por_severidad": self.por_severidad,
            "por_categoria": self.por_categoria,
            "mapa_calor": {str(p): v for p, v in self.mapa_calor.items()},
            "riesgo_promedio": round(self.riesgo_promedio, 2),
        }


class MotorRiesgo:
    """Procesa hallazgos y calcula su riesgo segun la metodologia del documento."""

    def procesar(self, hallazgos: list[Hallazgo]) -> ResumenRiesgo:
        """
        Enriquece cada hallazgo con probabilidad, impacto, nivel de riesgo y
        CVSS estimado, y devuelve un resumen agregado.
        """
        resumen = ResumenRiesgo()
        # Inicializar la cuadricula del mapa de calor (P=1..5, I=1..5).
        resumen.mapa_calor = {p: {i: 0 for i in range(1, 6)} for p in range(1, 6)}

        suma_riesgo = 0
        for h in hallazgos:
            impacto = IMPACTO_POR_CATEGORIA.get(h.categoria, 3)
            probabilidad = PROBABILIDAD_POR_SEVERIDAD.get(h.severidad, 3)
            valor = probabilidad * impacto

            h.impacto = impacto
            h.probabilidad = probabilidad
            h.nivel_riesgo = nivel_riesgo(valor)
            if h.cvss is None:
                h.cvss = CVSS_POR_SEVERIDAD.get(h.severidad, 5.0)

            # Agregados.
            resumen.por_nivel[h.nivel_riesgo] = resumen.por_nivel.get(h.nivel_riesgo, 0) + 1
            resumen.por_severidad[h.severidad.value] = resumen.por_severidad.get(h.severidad.value, 0) + 1
            resumen.por_categoria[h.categoria.value] = resumen.por_categoria.get(h.categoria.value, 0) + 1
            resumen.mapa_calor[probabilidad][impacto] += 1
            suma_riesgo += valor

        resumen.total = len(hallazgos)
        resumen.riesgo_promedio = (suma_riesgo / len(hallazgos)) if hallazgos else 0.0
        return resumen
