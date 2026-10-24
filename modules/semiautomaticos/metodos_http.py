"""
Modulo semiautomatico: metodos HTTP peligrosos y path traversal.

Cubre:
    RF-10   Identificar metodos HTTP peligrosos habilitados y vulnerabilidades
            de path traversal.
    Categoria OWASP: A01 - Broken Access Control.

Es "semiautomatico": consulta los metodos permitidos (OPTIONS) y realiza
pruebas controladas y no destructivas. El TRACE se comprueba activamente; PUT y
DELETE solo se reportan si el servidor los anuncia como permitidos, sin
enviarlos realmente (uso responsable: no se crean ni borran recursos). El path
traversal usa el patron de LINEA BASE (RNF-04) para evitar falsos positivos.
"""

from __future__ import annotations

import uuid

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


METODOS_PELIGROSOS = {
    "PUT": (Severidad.ALTA, "Permite subir archivos al servidor."),
    "DELETE": (Severidad.ALTA, "Permite eliminar recursos del servidor."),
    "TRACE": (Severidad.MEDIA, "Facilita ataques Cross-Site Tracing (XST)."),
    "CONNECT": (Severidad.MEDIA, "Puede permitir que el servidor actue como proxy."),
    "PATCH": (Severidad.MEDIA, "Permite modificaciones parciales de recursos."),
}

# Cargas de path traversal (lectura de un archivo del sistema, no destructivo).
CARGAS_TRAVERSAL = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]
# Marcadores que confirman la lectura de /etc/passwd.
MARCADORES_PASSWD = ("root:x:0:0:", "daemon:", "/bin/bash", "/usr/sbin/nologin")


@registrar_modulo
class MetodosHTTP(ModuloBase):
    nombre = "metodos_http"
    categoria_default = CategoriaOWASP.BROKEN_ACCESS

    def run(self):
        hallazgos = []
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        hallazgos += self._revisar_metodos(timeout)
        hallazgos += self._revisar_traversal(timeout)
        return hallazgos

    def _revisar_metodos(self, timeout):
        hallazgos = []
        try:
            resp = self.http.options(self.objetivo, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            self.logger.error("metodos_http: OPTIONS fallo: %s", exc)
            return hallazgos

        permitidos_raw = resp.headers.get("Allow", "") + "," + resp.headers.get("Public", "")
        permitidos = {m.strip().upper() for m in permitidos_raw.split(",") if m.strip()}
        self.logger.info("metodos_http: metodos anunciados: %s", ", ".join(sorted(permitidos)) or "(ninguno)")

        for metodo, (severidad, descripcion) in METODOS_PELIGROSOS.items():
            if metodo in permitidos:
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Metodo HTTP peligroso habilitado: {metodo}",
                    severidad=severidad,
                    evidencia=f"El servidor anuncia el metodo '{metodo}' como permitido (cabecera Allow). {descripcion}",
                    recomendacion=(
                        f"Deshabilite el metodo '{metodo}' si la aplicacion no lo requiere; "
                        "permita unicamente los metodos necesarios (GET, POST, HEAD)."
                    ),
                    ubicacion=self.objetivo,
                ))

        # TRACE: comprobacion activa (no destructiva).
        try:
            r = self.http.request("TRACE", self.objetivo, timeout=timeout)
            if r.status_code == 200 and "TRACE" in r.text.upper():
                if not any(h.titulo.endswith("TRACE") for h in hallazgos):
                    hallazgos.append(self.crear_hallazgo(
                        titulo="Metodo HTTP peligroso habilitado: TRACE",
                        severidad=Severidad.MEDIA,
                        evidencia="El servidor respondio a una peticion TRACE reflejando la solicitud (posible XST).",
                        recomendacion="Deshabilite el metodo TRACE en la configuracion del servidor web.",
                        ubicacion=self.objetivo,
                    ))
        except requests.RequestException:
            pass

        return hallazgos

    def _revisar_traversal(self, timeout):
        hallazgos = []
        # Linea base (RNF-04): respuesta a un parametro con valor inocuo.
        marcador = uuid.uuid4().hex
        try:
            base = self.http.get(self.objetivo, params={"file": marcador}, timeout=timeout)
            base_status = base.status_code
        except requests.RequestException:
            base_status = None

        for carga in CARGAS_TRAVERSAL:
            try:
                resp = self.http.get(self.objetivo, params={"file": carga}, timeout=timeout)
            except requests.RequestException:
                continue

            texto = resp.text
            if any(m in texto for m in MARCADORES_PASSWD):
                hallazgos.append(self.crear_hallazgo(
                    titulo="Posible path traversal confirmado",
                    severidad=Severidad.CRITICA,
                    evidencia=(
                        f"La carga '{carga}' en el parametro 'file' devolvio contenido "
                        f"caracteristico de /etc/passwd (HTTP {resp.status_code}), distinto "
                        f"de la linea base (HTTP {base_status})."
                    ),
                    recomendacion=(
                        "Valide y normalice las rutas de archivo del lado del servidor; nunca "
                        "construya rutas directamente a partir de la entrada del usuario. Use "
                        "listas blancas de archivos permitidos."
                    ),
                    ubicacion=f"{self.objetivo}?file=",
                ))
                break  # confirmado una vez, no insistir

        return hallazgos
