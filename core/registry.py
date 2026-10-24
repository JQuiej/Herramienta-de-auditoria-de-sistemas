"""
Registro de modulos de deteccion (RNF-01: modularidad).

Los modulos se registran a si mismos con el decorador @registrar_modulo. El
orquestador consulta este registro para saber que modulos existen y cuales
estan activados en la configuracion, sin acoplarse a ninguno en concreto.

Anadir un modulo nuevo = crear un archivo con una subclase de ModuloBase
decorada con @registrar_modulo, e importarlo en modules/__init__.py. El core
no se toca.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:  # solo para anotaciones; evita un import circular en runtime
    from modules.base import ModuloBase

# Diccionario global: nombre del modulo -> clase del modulo.
_REGISTRO: dict[str, "Type[ModuloBase]"] = {}


def registrar_modulo(clase: "Type[ModuloBase]") -> "Type[ModuloBase]":
    """Decorador que registra una clase de modulo por su atributo 'nombre'."""
    nombre = getattr(clase, "nombre", None)
    if not nombre or nombre == "base":
        raise ValueError(
            f"El modulo {clase.__name__} debe definir un atributo 'nombre' unico."
        )
    if nombre in _REGISTRO:
        raise ValueError(f"Modulo duplicado en el registro: '{nombre}'.")
    _REGISTRO[nombre] = clase
    return clase


def modulos_registrados() -> dict[str, "Type[ModuloBase]"]:
    """Devuelve una copia del registro completo de modulos."""
    return dict(_REGISTRO)


def obtener_modulo(nombre: str) -> "Type[ModuloBase] | None":
    """Devuelve la clase de un modulo por nombre, o None si no existe."""
    return _REGISTRO.get(nombre)
