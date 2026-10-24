"""
Modelo de datos central de la herramienta de auditoria.

Toda la informacion que producen los modulos de deteccion se representa
mediante una unica estructura: el Hallazgo (documento seccion 11.5.4).

Este diseno permite que modulos de naturaleza muy distinta (peticiones HTTP
simples, salida de herramientas externas en formatos diferentes) entreguen su
resultado de forma homogenea, sin que el motor de riesgo ni el generador de
reportes necesiten logica especial para cada modulo.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum


class Severidad(Enum):
    """Severidad de un hallazgo (documento seccion 11.5.4)."""

    CRITICA = "Critica"
    ALTA = "Alta"
    MEDIA = "Media"
    BAJA = "Baja"
    INFORMATIVA = "Informativa"


class CategoriaOWASP(Enum):
    """
    Categoria del OWASP Top 10 (2021) a la que corresponde el hallazgo.

    Se restringe a un conjunto cerrado de valores (documento seccion 11.5.4).
    Se incluye ademas RECONOCIMIENTO para los hallazgos informativos que
    produce el crawler y el modulo de tecnologias.
    """

    BROKEN_ACCESS = "A01 - Broken Access Control"
    CRYPTO_FAILURES = "A02 - Cryptographic Failures"
    INJECTION = "A03 - Injection"
    INSECURE_DESIGN = "A04 - Insecure Design"
    SECURITY_MISCONFIG = "A05 - Security Misconfiguration"
    VULNERABLE_COMPONENTS = "A06 - Vulnerable and Outdated Components"
    AUTH_FAILURES = "A07 - Identification and Authentication Failures"
    INTEGRITY_FAILURES = "A08 - Software and Data Integrity Failures"
    LOGGING_FAILURES = "A09 - Security Logging and Monitoring Failures"
    SSRF = "A10 - Server-Side Request Forgery"
    SUPPLY_CHAIN = "Software Supply Chain Failures"
    RECONOCIMIENTO = "Reconocimiento"


@dataclass
class Hallazgo:
    """
    Estructura homogenea que devuelven todos los modulos de deteccion.

    Campos (documento seccion 11.5.4):
        categoria       Categoria OWASP Top 10 (conjunto cerrado).
        severidad       Critica, alta, media, baja o informativa.
        evidencia       Detalle tecnico que respalda el hallazgo.
        recomendacion   Sugerencia de correccion para un equipo no especializado.
        modulo_origen   Modulo que genero el hallazgo (trazabilidad, RNF-07).
        cvss            Puntuacion 0.0-10.0; si es None, el motor de riesgo la
                        estima a partir de la severidad.
        id / timestamp  Identificador y marca de tiempo, generados al crear.
        titulo          Resumen corto del hallazgo.
        ubicacion       URL, ruta o parametro donde se detecto (opcional).
    """

    categoria: CategoriaOWASP
    severidad: Severidad
    evidencia: str
    recomendacion: str
    modulo_origen: str
    titulo: str = ""
    ubicacion: str = ""
    cvss: float | None = None
    # Valores de riesgo calculados por el motor (documento seccion 5 y 11.6.4).
    probabilidad: int | None = None
    impacto: int | None = None
    nivel_riesgo: str | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    def to_dict(self) -> dict:
        """Serializa el hallazgo a un diccionario apto para JSON."""
        datos = asdict(self)
        datos["categoria"] = self.categoria.value
        datos["severidad"] = self.severidad.value
        return datos

    def __str__(self) -> str:
        return f"[{self.severidad.value}] {self.titulo or self.categoria.value} ({self.modulo_origen})"
