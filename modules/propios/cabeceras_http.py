"""
Modulo propio: analisis de cabeceras HTTP de seguridad.

Cubre:
    RF-05   Detectar la ausencia o mala configuracion de cabeceras HTTP de
            seguridad.
    Categoria OWASP: A05 - Security Misconfiguration.

Es un modulo "propio" (documento seccion 11.5.3): realiza una peticion HTTP
directa y compara las cabeceras de la respuesta contra un catalogo de buenas
practicas. No envia payloads ni realiza ninguna accion intrusiva sobre el
objetivo, por lo que es seguro ejecutarlo contra un sistema en produccion.
"""

from __future__ import annotations

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


# Catalogo de cabeceras de seguridad esperadas: nombre -> (severidad, recomendacion).
CABECERAS_ESPERADAS = {
    "Strict-Transport-Security": (
        Severidad.ALTA,
        "Anada la cabecera 'Strict-Transport-Security' para forzar el uso de HTTPS "
        "y prevenir ataques de degradacion a HTTP.",
    ),
    "Content-Security-Policy": (
        Severidad.ALTA,
        "Defina una 'Content-Security-Policy' que restrinja el origen de scripts y "
        "recursos, mitigando ataques de Cross-Site Scripting (XSS).",
    ),
    "X-Content-Type-Options": (
        Severidad.MEDIA,
        "Anada 'X-Content-Type-Options: nosniff' para evitar que el navegador "
        "interprete archivos con un tipo MIME distinto al declarado.",
    ),
    "X-Frame-Options": (
        Severidad.MEDIA,
        "Anada 'X-Frame-Options: DENY' o 'SAMEORIGIN' para proteger el portal "
        "contra ataques de clickjacking.",
    ),
    "Referrer-Policy": (
        Severidad.BAJA,
        "Defina una 'Referrer-Policy' (por ejemplo 'no-referrer-when-downgrade') "
        "para controlar la informacion de referencia enviada a terceros.",
    ),
}


@registrar_modulo
class CabecerasHTTP(ModuloBase):
    nombre = "cabeceras_http"
    categoria_default = CategoriaOWASP.SECURITY_MISCONFIG

    def run(self):
        hallazgos = []
        timeout = int(self.config.get("timeouts", {}).get("por_modulo_seg", 30))
        timeout = min(timeout, 30)  # una sola peticion no necesita mas

        try:
            resp = self.http.get(self.objetivo, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            # Objetivo inaccesible: registrar y devolver vacio (RNF-02).
            self.logger.error("cabeceras_http: objetivo inaccesible: %s", exc)
            return hallazgos

        # Si el objetivo respondio con un error, avisar: una pagina 4xx/5xx no
        # refleja las cabeceras reales del sitio y falsearia el resto de hallazgos.
        if resp.status_code >= 400:
            hallazgos.append(
                self.crear_hallazgo(
                    titulo=f"El objetivo respondio con HTTP {resp.status_code}",
                    severidad=Severidad.INFORMATIVA,
                    evidencia=(
                        f"La peticion a {self.objetivo} devolvio HTTP {resp.status_code}. "
                        "Los hallazgos de este escaneo pueden estar incompletos: "
                        "verifique que la URL sea correcta y accesible."
                    ),
                    recomendacion=(
                        "Confirme la URL del objetivo. Si requiere autenticacion, "
                        "active el 'Escaneo autenticado' con credenciales validas."
                    ),
                    ubicacion=self.objetivo,
                )
            )

        presentes = {k.lower() for k in resp.headers}

        for cabecera, (severidad, recomendacion) in CABECERAS_ESPERADAS.items():
            if cabecera.lower() not in presentes:
                hallazgos.append(
                    self.crear_hallazgo(
                        titulo=f"Cabecera de seguridad ausente: {cabecera}",
                        severidad=severidad,
                        evidencia=(
                            f"La respuesta de {self.objetivo} (HTTP {resp.status_code}) "
                            f"no incluye la cabecera '{cabecera}'."
                        ),
                        recomendacion=recomendacion,
                        ubicacion=self.objetivo,
                    )
                )

        # Comprobacion adicional: divulgacion de tecnologia por 'Server'/'X-Powered-By'.
        for cabecera_info in ("Server", "X-Powered-By"):
            valor = resp.headers.get(cabecera_info)
            if valor:
                hallazgos.append(
                    self.crear_hallazgo(
                        titulo=f"Divulgacion de tecnologia en cabecera '{cabecera_info}'",
                        severidad=Severidad.INFORMATIVA,
                        evidencia=f"La cabecera '{cabecera_info}' expone: {valor}",
                        recomendacion=(
                            f"Configure el servidor para ocultar o minimizar el valor "
                            f"de la cabecera '{cabecera_info}' y no revelar versiones."
                        ),
                        ubicacion=self.objetivo,
                    )
                )

        return hallazgos
