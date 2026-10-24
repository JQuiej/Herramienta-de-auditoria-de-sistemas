"""
Carga y validacion de la configuracion de la auditoria (config.yaml).

Cubre:
    RF-01  Configurar la URL del objetivo antes de iniciar el analisis.
    RF-03  Activar/desactivar cada modulo de deteccion de forma independiente.
    Caso de uso "Configurar auditoria", flujos alternativos:
        A1  URL invalida (sin esquema http:// o https://): error, no continua.
        A2  Autorizacion no confirmada: se bloquea el inicio (ver orquestador).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ConfigError(Exception):
    """Error de configuracion invalida."""


@dataclass
class Configuracion:
    """Configuracion validada de una auditoria."""

    url: str
    nombre: str
    autorizado: bool
    modulos: dict[str, bool]
    timeouts: dict[str, int]
    opciones: dict = field(default_factory=dict)
    ruta: Path | None = None

    def modulo_activo(self, nombre: str) -> bool:
        """Indica si un modulo esta activado (RF-03). Por defecto, desactivado."""
        return bool(self.modulos.get(nombre, False))

    def timeout_modulo(self) -> int:
        """Tiempo maximo por modulo en segundos (RNF-05)."""
        return int(self.timeouts.get("por_modulo_seg", 300))


def validar_url(url: str) -> str:
    """
    Valida que la URL incluya esquema http:// o https:// (flujo alternativo A1).
    Devuelve la URL normalizada o lanza ConfigError.
    """
    if not url or not isinstance(url, str):
        raise ConfigError("A1: la URL del objetivo es obligatoria (RF-01).")
    partes = urlparse(url.strip())
    if partes.scheme not in ("http", "https"):
        raise ConfigError(
            f"A1: URL invalida '{url}'. Debe incluir el esquema http:// o https://."
        )
    if not partes.netloc:
        raise ConfigError(f"A1: URL invalida '{url}'. Falta el dominio o host.")
    return url.strip()


def cargar_config(ruta: str | Path) -> Configuracion:
    """
    Carga config.yaml, valida sus campos y devuelve un objeto Configuracion.
    """
    ruta = Path(ruta)
    if not ruta.exists():
        raise ConfigError(f"No se encontro el archivo de configuracion: {ruta}")

    with ruta.open("r", encoding="utf-8") as fh:
        datos = yaml.safe_load(fh) or {}

    objetivo = datos.get("objetivo", {})
    url = validar_url(objetivo.get("url", ""))
    nombre = objetivo.get("nombre") or "auditoria"

    modulos = datos.get("modulos", {})
    if not isinstance(modulos, dict):
        raise ConfigError("La seccion 'modulos' debe ser un mapa nombre: true/false.")

    timeouts = datos.get("timeouts", {}) or {}

    return Configuracion(
        url=url,
        nombre=nombre,
        autorizado=bool(datos.get("autorizado", False)),
        modulos=modulos,
        timeouts=timeouts,
        opciones=datos.get("opciones", {}) or {},
        ruta=ruta,
    )
