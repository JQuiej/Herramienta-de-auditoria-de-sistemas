"""
Base comun para los modulos que envuelven herramientas externas (fase 5).

Todas las herramientas integradas siguen el mismo patron (documento seccion
11.6.3):
    1. Localizar el binario correspondiente.
    2. Construir el comando con opciones conservadoras (entorno de auditoria
       responsable: sin payloads destructivos).
    3. Ejecutarlo con un limite de tiempo (RNF-05).
    4. Traducir su salida al modelo de datos comun (Hallazgo).

Si el binario no esta instalado o la ejecucion falla, el modulo lo registra y
devuelve una lista vacia, sin interrumpir la auditoria (RNF-02).
"""

from __future__ import annotations

import shlex
import shutil
import subprocess

from modules.base import ModuloBase


class HerramientaExterna(ModuloBase):
    """Clase base para wrappers de herramientas de linea de comandos."""

    # Nombre(s) del binario a localizar (el primero que exista se usa).
    binarios: list[str] = []

    # Puente a WSL: si el binario no esta en Windows pero si dentro de WSL, la
    # herramienta lo ejecuta a traves de 'wsl'. Cacheados a nivel de clase.
    _wsl_disponible: bool | None = None
    _host_wsl: str | None = None

    # Estado por instancia (se fija al localizar el binario).
    _via_wsl: bool = False

    # --------------------------------------------------------------- WSL
    @classmethod
    def _hay_wsl(cls) -> bool:
        """
        Comprueba (una vez) si WSL puede EJECUTAR comandos realmente. No basta con
        que este instalado: WSL2 puede estar presente pero sin poder arrancar (falta
        'Plataforma de maquina virtual' o virtualizacion del BIOS). Por eso se corre
        un comando de prueba en lugar de 'wsl --status'.
        """
        if cls._wsl_disponible is None:
            try:
                r = subprocess.run(["wsl", "bash", "-lc", "echo __WSLOK__"],
                                   capture_output=True, timeout=12)
                salida = (r.stdout or b"").replace(b"\x00", b"")  # wsl puede emitir UTF-16
                cls._wsl_disponible = (r.returncode == 0 and b"__WSLOK__" in salida)
            except Exception:
                cls._wsl_disponible = False
        return cls._wsl_disponible

    def _bin_en_wsl(self, nombre: str) -> bool:
        """¿Existe el binario dentro de WSL? (usa un shell de login para cargar PATH)."""
        try:
            r = subprocess.run(
                ["wsl", "bash", "-lc", f"command -v {shlex.quote(nombre)}"],
                capture_output=True, text=True, timeout=12,
            )
            return r.returncode == 0 and bool(r.stdout.strip())
        except Exception:
            return False

    @classmethod
    def _host_windows_desde_wsl(cls) -> str:
        """IP del host Windows vista desde WSL2 (gateway por defecto, modo NAT)."""
        if cls._host_wsl is None:
            try:
                r = subprocess.run(
                    ["wsl", "bash", "-lc", "ip route show default | awk '{print $3}'"],
                    capture_output=True, text=True, timeout=10,
                )
                cls._host_wsl = (r.stdout.strip().splitlines() or [""])[0].strip()
            except Exception:
                cls._host_wsl = ""
        return cls._host_wsl

    @staticmethod
    def _traducir_localhost(arg: str, host: str) -> str:
        """Reemplaza localhost/127.0.0.1 por la IP del host Windows (para WSL)."""
        if not host:
            return arg
        return arg.replace("127.0.0.1", host).replace("localhost", host)

    def localizar_binario(self) -> str | None:
        """Devuelve la ruta del primer binario disponible (Windows o, si no, WSL)."""
        for nombre in self.binarios:
            ruta = shutil.which(nombre)
            if ruta:
                self._via_wsl = False
                return ruta
        # Respaldo: buscarlo dentro de WSL.
        if self._hay_wsl():
            for nombre in self.binarios:
                if self._bin_en_wsl(nombre):
                    self._via_wsl = True
                    self._bin_wsl = nombre
                    self.logger.info("%s: binario '%s' encontrado en WSL; se ejecutara via wsl.",
                                     self.nombre, nombre)
                    self.emitir(f"usando '{nombre}' desde WSL")
                    # Se devuelve el NOMBRE: comando[0] sera el binario y
                    # ejecutar_comando lo envuelve con 'wsl bash -lc'.
                    return nombre
        return None

    def ejecutar_comando(self, comando: list[str], timeout: int) -> subprocess.CompletedProcess | None:
        """
        Ejecuta un comando externo con limite de tiempo. Devuelve el resultado
        o None si hubo timeout o error de ejecucion (registrado en el log).
        Si el binario esta en WSL, el comando se ejecuta a traves de 'wsl' y se
        traduce localhost/127.0.0.1 a la IP del host Windows.
        """
        if getattr(self, "_via_wsl", False):
            host = self._host_windows_desde_wsl()
            traducido = [self._traducir_localhost(a, host) for a in comando]
            cmd_str = " ".join(shlex.quote(a) for a in traducido)
            comando = ["wsl", "bash", "-lc", cmd_str]
        self.logger.debug("%s: ejecutando -> %s", self.nombre, " ".join(comando))
        try:
            return subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.logger.warning(
                "%s: la herramienta excedio el limite de %ss y fue detenida (RNF-05).",
                self.nombre, timeout,
            )
        except (OSError, ValueError) as exc:
            self.logger.error("%s: fallo al ejecutar la herramienta: %s", self.nombre, exc)
        return None

    def _binario_ausente(self):
        """Registra la ausencia del binario y devuelve una lista vacia (RNF-02)."""
        self.logger.warning(
            "%s: no se encontro ninguno de los binarios %s en el PATH; el modulo se "
            "omite. Instale la herramienta para habilitarlo.",
            self.nombre, self.binarios,
        )
        return []

    def timeout(self) -> int:
        return int(self.config.get("timeouts", {}).get("por_modulo_seg", 300))

    def contexto(self) -> dict:
        return self.config.get("contexto") or {}
