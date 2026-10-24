"""
Modulo propio: analisis de atributos de seguridad de las cookies.

Cubre:
    RF-06   Verificar los atributos de seguridad de las cookies
            (Secure, HttpOnly, SameSite).
    Categoria OWASP: A02 - Cryptographic Failures.

Es un modulo "propio": realiza una peticion HTTP directa e inspecciona las
cabeceras 'Set-Cookie' de la respuesta. No es intrusivo.
"""

from __future__ import annotations

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


@registrar_modulo
class Cookies(ModuloBase):
    nombre = "cookies"
    categoria_default = CategoriaOWASP.CRYPTO_FAILURES

    def run(self):
        hallazgos = []
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        try:
            resp = self.http.get(self.objetivo, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            self.logger.error("cookies: objetivo inaccesible: %s", exc)
            return hallazgos

        # requests no expone facilmente varios Set-Cookie; usamos la libreria
        # raw para conservar cada cookie con sus atributos.
        set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        if not set_cookies:
            # Fallback: al menos revisamos el jar de cookies.
            set_cookies = [
                f"{c.name}={c.value}" + ("; Secure" if c.secure else "")
                for c in resp.cookies
            ]

        if not set_cookies:
            self.logger.info("cookies: el objetivo no establece cookies.")
            return hallazgos

        es_https = self.objetivo.lower().startswith("https://")

        for raw in set_cookies:
            nombre_cookie = raw.split("=", 1)[0].strip()
            atributos = raw.lower()

            if "httponly" not in atributos:
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Cookie sin atributo HttpOnly: {nombre_cookie}",
                    severidad=Severidad.MEDIA,
                    evidencia=f"La cookie '{nombre_cookie}' no incluye el atributo HttpOnly.",
                    recomendacion=(
                        "Anada el atributo 'HttpOnly' a la cookie para impedir que sea "
                        "accesible desde JavaScript y mitigar el robo por XSS."
                    ),
                    ubicacion=self.objetivo,
                ))

            if es_https and "secure" not in atributos:
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Cookie sin atributo Secure: {nombre_cookie}",
                    severidad=Severidad.ALTA,
                    evidencia=f"La cookie '{nombre_cookie}' no incluye el atributo Secure sobre HTTPS.",
                    recomendacion=(
                        "Anada el atributo 'Secure' para que la cookie solo se transmita "
                        "por conexiones HTTPS cifradas."
                    ),
                    ubicacion=self.objetivo,
                ))

            if "samesite" not in atributos:
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Cookie sin atributo SameSite: {nombre_cookie}",
                    severidad=Severidad.BAJA,
                    evidencia=f"La cookie '{nombre_cookie}' no define el atributo SameSite.",
                    recomendacion=(
                        "Defina 'SameSite=Strict' o 'SameSite=Lax' para reducir el riesgo "
                        "de ataques de Cross-Site Request Forgery (CSRF)."
                    ),
                    ubicacion=self.objetivo,
                ))

        return hallazgos
