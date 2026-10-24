"""
Orquestador de la auditoria (Diagrama de flujo 1: Ejecutar auditoria).

Responsabilidades:
    RF-02   Bloquear la ejecucion si no se ha confirmado la autorizacion.
    RF-03   Ejecutar unicamente los modulos activados en la configuracion.
    RNF-02  Tolerancia a fallos: el fallo de un modulo individual no interrumpe
            la ejecucion del resto de la auditoria.
    RNF-03  Uso responsable: ninguna prueba se ejecuta sin autorizacion.

El orquestador NO detecta nada por si mismo: instancia los modulos activados,
recorre cada uno de forma aislada y consolida sus hallazgos en un unico
reporte, que luego alimenta al motor de riesgo y al generador de reportes.
"""

from __future__ import annotations

import logging
import time

from core.config_loader import Configuracion
from core.models import Hallazgo
from core.registry import modulos_registrados


class AutorizacionError(PermissionError):
    """Se intento ejecutar la auditoria sin autorizacion confirmada (RF-02)."""


class Orquestador:
    """Coordina la ejecucion de los modulos de deteccion sobre un objetivo."""

    def __init__(self, config: Configuracion, logger: logging.Logger, listener=None):
        self.config = config
        self.logger = logger
        # Listener opcional: funcion que recibe eventos de progreso durante la
        # auditoria. La interfaz grafica lo usa para actualizarse en vivo; la
        # CLI no lo necesita (queda en None). Eventos emitidos:
        #   {"tipo": "inicio", "modulos": [nombres]}
        #   {"tipo": "modulo_inicio", "nombre": str}
        #   {"tipo": "modulo_fin", "nombre": str, "hallazgos": int}
        #   {"tipo": "modulo_error", "nombre": str, "error": str}
        #   {"tipo": "fin", "total": int}
        self.listener = listener
        # Contexto compartido entre modulos: el crawler deposita aqui las URLs
        # con parametros y los formularios descubiertos, y los modulos de
        # inyeccion (fases siguientes) los consumen. Es la via de comunicacion
        # entre modulos sin acoplarlos entre si.
        self.contexto: dict = {
            "urls_con_parametros": [],
            "formularios": [],
            "rutas_descubiertas": [],
            "auth": {},
        }

    def _verificar_autorizacion(self) -> None:
        """
        Gate de autorizacion (RF-02, RNF-03, flujo alternativo A2).

        Es la primera y unica puerta antes de tocar el objetivo. Si no esta
        confirmada, se aborta sin instanciar ningun modulo de red.
        """
        if not self.config.autorizado:
            self.logger.error(
                "AUDITORIA BLOQUEADA (RF-02): no se ha confirmado la autorizacion "
                "para auditar el objetivo. Marque 'autorizado: true' en config.yaml "
                "solo si cuenta con permiso explicito de la cooperativa."
            )
            raise AutorizacionError(
                "Auditoria bloqueada: autorizacion no confirmada (RF-02)."
            )
        self.logger.info("Autorizacion confirmada. Objetivo: %s", self.config.url)

    def _modulos_a_ejecutar(self) -> list:
        """
        Selecciona, del registro global, las clases de modulo activadas en la
        configuracion (RF-03). Advierte si un modulo activado no existe.
        """
        registrados = modulos_registrados()
        seleccionados = []
        for nombre, activo in self.config.modulos.items():
            if not activo:
                continue
            clase = registrados.get(nombre)
            if clase is None:
                self.logger.warning(
                    "Modulo '%s' activado en config pero no encontrado en el registro. "
                    "Se omite.", nombre,
                )
                continue
            seleccionados.append(clase)
        return seleccionados

    def ejecutar(self) -> list[Hallazgo]:
        """
        Ejecuta la auditoria completa y devuelve la lista consolidada de
        hallazgos. Implementa el Diagrama de flujo 1.
        """
        self._verificar_autorizacion()

        clases = self._modulos_a_ejecutar()
        if not clases:
            self.logger.warning("No hay modulos activos que ejecutar (RF-03).")
            return []

        # Paso previo opcional: iniciar sesion para el escaneo autenticado.
        self._autenticar_si_procede()

        self.logger.info("Modulos a ejecutar: %s", ", ".join(c.nombre for c in clases))
        self._emitir({"tipo": "inicio", "modulos": [c.nombre for c in clases]})

        hallazgos: list[Hallazgo] = []
        for clase in clases:
            nombre = clase.nombre
            inicio = time.perf_counter()
            self._emitir({"tipo": "modulo_inicio", "nombre": nombre})
            try:
                self.logger.info("--> Ejecutando modulo '%s'...", nombre)
                modulo = clase(self.config.url, self._config_modulo(), self.logger)
                resultado = modulo.run() or []
                hallazgos.extend(resultado)
                duracion = time.perf_counter() - inicio
                self.logger.info(
                    "<-- Modulo '%s' finalizado: %d hallazgo(s) en %.1fs.",
                    nombre, len(resultado), duracion,
                )
                self._emitir({"tipo": "modulo_fin", "nombre": nombre, "hallazgos": len(resultado)})
            except Exception as exc:  # RNF-02: aislar el fallo, continuar
                self.logger.error(
                    "Modulo '%s' fallo y fue omitido (RNF-02): %s", nombre, exc,
                    exc_info=True,
                )
                self._emitir({"tipo": "modulo_error", "nombre": nombre, "error": str(exc)})
                continue

        self.logger.info(
            "Auditoria finalizada. Total de hallazgos consolidados: %d", len(hallazgos)
        )
        self._emitir({"tipo": "fin", "total": len(hallazgos)})
        return hallazgos

    def _autenticar_si_procede(self) -> None:
        """
        Si la configuracion incluye credenciales de login, inicia sesion antes de
        ejecutar los modulos y guarda el estado de sesion en el contexto, para
        que los modulos trabajen autenticados (escaneo autenticado).
        """
        login = (self.config.opciones or {}).get("login") or {}
        if not login.get("realizar"):
            return
        # Completar la URL de login con la del objetivo si viene relativa/ausente.
        if not login.get("url"):
            login["url"] = self.config.url
        self._emitir({"tipo": "login_inicio"})
        self.logger.info("Iniciando sesion para escaneo autenticado en %s...", login["url"])
        try:
            from core.autenticador import autenticar
            auth = autenticar(login, self.logger)
        except Exception as exc:
            self.logger.error("Fallo el proceso de login: %s", exc)
            auth = {"exito": False, "evidencia": str(exc), "cookies": {}, "headers": {}, "storage_state": None}
        self.contexto["auth"] = auth
        self._emitir({"tipo": "login_fin", "exito": auth.get("exito", False),
                      "evidencia": auth.get("evidencia", "")})

    def _emitir(self, evento: dict) -> None:
        """Envia un evento de progreso al listener, si hay uno registrado."""
        if self.listener is not None:
            try:
                self.listener(evento)
            except Exception as exc:  # el listener nunca debe romper la auditoria
                self.logger.debug("listener fallo al procesar evento: %s", exc)

    def _emitir_modulo(self, nombre: str, mensaje: str) -> None:
        """Reenvia una linea de progreso en vivo de un modulo hacia el listener."""
        self._emitir({"tipo": "modulo_log", "nombre": nombre, "mensaje": mensaje})

    def _config_modulo(self) -> dict:
        """Configuracion que se pasa a cada modulo (incluye timeouts, RNF-05)."""
        return {
            "timeouts": self.config.timeouts,
            "nombre_objetivo": self.config.nombre,
            "contexto": self.contexto,
            "opciones": self.config.opciones,
            "auth": self.contexto.get("auth", {}),
            "emitir": self._emitir_modulo,
        }
