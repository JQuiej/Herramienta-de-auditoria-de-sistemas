"""
Modulo propio: deteccion de archivos y directorios sensibles expuestos.

Cubre:
    RF-08   Detectar archivos y directorios sensibles expuestos publicamente.
    Categoria OWASP: A05 - Security Misconfiguration.

Patron de LINEA BASE (RNF-04, documento seccion 11.6.2):
    Algunos servidores responden con exito a cualquier ruta solicitada, lo que
    simularia una exposicion inexistente. Para evitar ese falso positivo, antes
    de reportar una ruta sensible el modulo solicita una ruta aleatoria que con
    certeza NO existe y usa esa respuesta como referencia. Solo se reporta un
    hallazgo cuando la respuesta de la ruta sensible difiere de la linea base
    (por ejemplo, 200 frente al 404 de la ruta inexistente).
"""

from __future__ import annotations

import uuid

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


# Rutas sensibles a comprobar: ruta -> (severidad, descripcion).
RUTAS_SENSIBLES = {
    "/.git/config": (Severidad.CRITICA, "Repositorio Git expuesto (codigo fuente e historial)."),
    "/.env": (Severidad.CRITICA, "Archivo de variables de entorno con posibles credenciales."),
    "/backup.sql": (Severidad.CRITICA, "Copia de seguridad de base de datos expuesta."),
    "/config.php.bak": (Severidad.ALTA, "Copia de respaldo de un archivo de configuracion."),
    "/.htaccess": (Severidad.MEDIA, "Archivo de configuracion de Apache accesible."),
    "/phpinfo.php": (Severidad.ALTA, "Pagina phpinfo() que revela la configuracion del servidor."),
    "/admin/": (Severidad.MEDIA, "Directorio de administracion accesible."),
    "/server-status": (Severidad.MEDIA, "Pagina de estado del servidor Apache expuesta."),
    "/.svn/entries": (Severidad.ALTA, "Metadatos de Subversion expuestos."),
    "/robots.txt": (Severidad.INFORMATIVA, "robots.txt puede revelar rutas ocultas."),
}


@registrar_modulo
class ArchivosExpuestos(ModuloBase):
    nombre = "archivos_expuestos"
    categoria_default = CategoriaOWASP.SECURITY_MISCONFIG

    def run(self):
        hallazgos = []
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        # --- 1. Establecer la LINEA BASE (RNF-04) ---
        baseline = self._obtener_linea_base(timeout)
        if baseline is None:
            self.logger.error("archivos_expuestos: objetivo inaccesible, se omite el modulo.")
            return hallazgos
        base_status, base_len = baseline
        self.logger.info(
            "archivos_expuestos: linea base -> status %s, longitud %s bytes.",
            base_status, base_len,
        )

        # --- 2. Comprobar cada ruta sensible contra la linea base ---
        for ruta, (severidad, descripcion) in RUTAS_SENSIBLES.items():
            url = self.objetivo + ruta
            try:
                # allow_redirects=True: se sigue la redireccion hasta su destino
                # final, igual que hace un navegador. Asi una ruta que responde
                # 3xx y termina en 404 NO se reporta como expuesta (evita el
                # falso positivo de contar una simple redireccion como acceso).
                resp = self.http.get(url, timeout=timeout, allow_redirects=True)
            except requests.RequestException as exc:
                self.logger.debug("archivos_expuestos: fallo al solicitar %s: %s", url, exc)
                continue

            self.emitir(f"probando {ruta} -> HTTP {resp.status_code}")
            if self._es_exposicion_real(resp, base_status, base_len):
                self.emitir(f"  ! EXPUESTO: {ruta}")
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Recurso sensible expuesto: {ruta}",
                    severidad=severidad,
                    evidencia=(
                        f"{url} respondio HTTP {resp.status_code} "
                        f"({len(resp.content)} bytes), distinto de la linea base "
                        f"(HTTP {base_status}). {descripcion}"
                    ),
                    recomendacion=(
                        f"Restrinja o elimine el acceso publico a '{ruta}'. Configure el "
                        "servidor para devolver 404/403 en rutas y archivos sensibles."
                    ),
                    ubicacion=url,
                ))

        return hallazgos

    def _obtener_linea_base(self, timeout):
        """Solicita una ruta aleatoria inexistente y devuelve (status, longitud)."""
        ruta_falsa = f"/{uuid.uuid4().hex}-no-existe-{uuid.uuid4().hex}"
        try:
            # Se siguen redirecciones tambien en la linea base, para comparar el
            # destino final de una ruta inexistente con el de las rutas sensibles.
            resp = self.http.get(self.objetivo + ruta_falsa, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            return None
        return resp.status_code, len(resp.content)

    @staticmethod
    def _es_exposicion_real(resp, base_status, base_len) -> bool:
        """
        Un recurso se considera realmente expuesto solo si, tras seguir cualquier
        redireccion, su respuesta FINAL es 2xx (contenido servido de verdad) y
        distinta de la linea base.

        Se exige codigo 2xx (200-299): un 3xx ya se resolvio al destino final por
        allow_redirects=True, y un 4xx/5xx no es exposicion. Esto evita el falso
        positivo de tratar una simple redireccion (301/302) como acceso real, y
        el de los servidores permisivos que responden igual a cualquier ruta
        inexistente (RNF-04).
        """
        if not (200 <= resp.status_code < 300):
            return False
        if resp.status_code == base_status and abs(len(resp.content) - base_len) < 50:
            # Responde igual que a una ruta que no existe -> servidor permisivo.
            return False
        return True
