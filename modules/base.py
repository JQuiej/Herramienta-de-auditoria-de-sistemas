"""
Interfaz comun de todos los modulos de deteccion (RNF-01: modularidad).

Cada tecnica de deteccion se implementa como una clase que hereda de
ModuloBase. Para anadir un modulo nuevo basta con crear un archivo con una
subclase y registrarlo; el resto del sistema no cambia.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from core.models import CategoriaOWASP, Hallazgo


# Cabeceras por defecto de la sesion HTTP compartida.
#
# MOTIVO (correccion de un problema real): muchos sitios rechazan con 403/429 las
# peticiones cuyo User-Agent es el de 'python-requests'. Una pagina de error no
# incluye ninguna cabecera de seguridad ni cookies, de modo que TODOS los
# objetivos parecian igual de vulnerables ("da los mismos datos a todas las
# paginas"). Presentandonos como un navegador real obtenemos la respuesta
# autentica del objetivo y cada sitio arroja sus propios resultados.
CABECERAS_NAVEGADOR = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
}


class ModuloBase(ABC):
    """
    Clase base abstracta para un modulo de deteccion.

    Atributos de clase que cada modulo concreto debe definir:
        nombre              Identificador corto y unico del modulo. Se usa como
                            modulo_origen en cada hallazgo (trazabilidad, RNF-07).
        categoria_default   Categoria OWASP por defecto de sus hallazgos.
    """

    nombre: str = "base"
    categoria_default: CategoriaOWASP = CategoriaOWASP.SECURITY_MISCONFIG

    def __init__(self, objetivo: str, config: dict, logger: logging.Logger):
        self.objetivo = objetivo.rstrip("/")
        self.config = config
        self.logger = logger
        self._http = None

    def emitir(self, mensaje: str) -> None:
        """
        Envia una linea de progreso EN VIVO a la consola de la interfaz (si hay un
        emisor registrado). Permite que, por ejemplo, el crawler muestre cada
        endpoint segun lo descubre, en tiempo real. Nunca interrumpe el modulo.
        """
        emisor = self.config.get("emitir")
        if emisor:
            try:
                emisor(self.nombre, mensaje)
            except Exception:
                pass

    @property
    def http(self):
        """
        Sesion HTTP compartida (requests.Session) que ya incluye la autenticacion
        si la auditoria se ejecuto con login. Los modulos deben usar self.http.get
        en lugar de requests.get para trabajar detras del login cuando corresponda.
        """
        if self._http is None:
            import requests
            sesion = requests.Session()
            # Presentarse como un navegador real para obtener la respuesta
            # autentica del objetivo (evita el 403 que igualaba a todos los sitios).
            sesion.headers.update(CABECERAS_NAVEGADOR)
            auth = self.config.get("auth") or {}
            cookies = auth.get("cookies") or {}
            headers = auth.get("headers") or {}
            if cookies:
                sesion.cookies.update(cookies)
            if headers:  # las cabeceras de autenticacion (p.ej. Authorization) tienen prioridad
                sesion.headers.update(headers)
            self._http = sesion
        return self._http

    @abstractmethod
    def run(self) -> list[Hallazgo]:
        """
        Ejecuta la tecnica de deteccion y devuelve una lista de hallazgos.

        No debe lanzar excepciones hacia el orquestador para casos esperados
        (objetivo inaccesible, herramienta ausente): registrar el error y
        devolver una lista vacia. El orquestador aisla fallos igualmente
        (RNF-02), pero un modulo bien hecho degrada con elegancia.
        """
        raise NotImplementedError

    def crear_hallazgo(self, **kwargs) -> Hallazgo:
        """
        Fabrica un Hallazgo rellenando automaticamente el modulo_origen y la
        categoria por defecto si no se especifican. Garantiza la trazabilidad.
        """
        kwargs.setdefault("modulo_origen", self.nombre)
        kwargs.setdefault("categoria", self.categoria_default)
        return Hallazgo(**kwargs)
