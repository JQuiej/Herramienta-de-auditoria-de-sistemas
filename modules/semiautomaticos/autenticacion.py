"""
Modulo semiautomatico: evaluacion de controles de autenticacion.

Cubre:
    RF-11   Evaluar los controles de autenticacion del objetivo SIN realizar
            ataques de fuerza bruta reales.
    Categoria OWASP: A07 - Identification and Authentication Failures.

USO RESPONSABLE (documento: "que queda fuera" y seccion 11.6.5):
    Este modulo NO intenta adivinar credenciales. Evalua unicamente la PRESENCIA
    de controles mediante un numero muy reducido y acotado de intentos con
    credenciales aleatorias e invalidas (nunca reales), para observar si el
    sistema:
        - Aplica limite de intentos / bloqueo (rate limiting o lockout).
        - Revela informacion que facilite la enumeracion de usuarios.
        - Configura de forma segura la cookie de sesion.
    El numero de intentos esta limitado por diseno (tope de 5).

Configuracion (config.yaml -> opciones.autenticacion):
    url_login:      URL del formulario/endpoint de login (opcional; si no se da,
                    se intenta detectar un formulario con campo de contrasena a
                    partir del contexto que dejo el crawler).
    campo_usuario:  nombre del campo de usuario (por defecto 'username').
    campo_password: nombre del campo de contrasena (por defecto 'password').
    max_intentos:   numero de intentos fallidos a probar (por defecto 4, tope 5).
"""

from __future__ import annotations

import uuid

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


@registrar_modulo
class Autenticacion(ModuloBase):
    nombre = "autenticacion"
    categoria_default = CategoriaOWASP.AUTH_FAILURES

    def run(self):
        hallazgos = []
        opciones = self.config.get("opciones", {}).get("autenticacion", {})
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        objetivo_login = opciones.get("url_login") or self._detectar_login()
        if not objetivo_login:
            self.logger.info(
                "autenticacion: no se indico url_login ni se detecto un formulario de "
                "login; el modulo no tiene endpoint que evaluar."
            )
            hallazgos.append(self.crear_hallazgo(
                titulo="No se pudo evaluar el control de autenticacion",
                severidad=Severidad.INFORMATIVA,
                evidencia=(
                    "No se proporciono 'opciones.autenticacion.url_login' ni el crawler "
                    "detecto un formulario con campo de contrasena."
                ),
                recomendacion=(
                    "Indique la URL del formulario de login en config.yaml para evaluar "
                    "sus controles de autenticacion."
                ),
                ubicacion=self.objetivo,
            ))
            return hallazgos

        campo_usuario = opciones.get("campo_usuario", "username")
        campo_password = opciones.get("campo_password", "password")
        max_intentos = min(int(opciones.get("max_intentos", 4)), 5)  # tope de 5

        self.logger.info(
            "autenticacion: evaluando %s con %d intento(s) invalido(s) (sin fuerza bruta).",
            objetivo_login, max_intentos,
        )

        respuestas = []
        for _ in range(max_intentos):
            datos = {
                campo_usuario: f"user_{uuid.uuid4().hex[:8]}",
                campo_password: uuid.uuid4().hex[:12],
            }
            try:
                # Usar la sesion compartida (self.http) para reutilizar el
                # User-Agent de navegador y la sesion autenticada si la hubiera.
                r = self.http.post(objetivo_login, data=datos, timeout=timeout, allow_redirects=False)
                respuestas.append(r)
            except requests.RequestException as exc:
                self.logger.debug("autenticacion: intento fallido de peticion: %s", exc)

        if not respuestas:
            self.logger.error("autenticacion: el endpoint de login no respondio.")
            return hallazgos

        hallazgos += self._evaluar_rate_limiting(respuestas, objetivo_login)
        hallazgos += self._evaluar_enumeracion(respuestas, objetivo_login)
        hallazgos += self._evaluar_cookie_sesion(respuestas[0], objetivo_login)
        return hallazgos

    def _detectar_login(self):
        """Busca en el contexto (crawler) un formulario con campo de contrasena."""
        contexto = self.config.get("contexto") or {}
        for form in contexto.get("formularios", []):
            if any(c.get("tipo", "").lower() == "password" for c in form.get("campos", [])):
                return form.get("action_absoluta")
        return None

    def _evaluar_rate_limiting(self, respuestas, url):
        """Comprueba si aparece algun indicio de limite de intentos / bloqueo."""
        hallazgos = []
        codigos = [r.status_code for r in respuestas]
        indicios_bloqueo = any(
            r.status_code in (429, 423) or
            any(p in r.text.lower() for p in ("bloque", "demasiados intentos", "too many", "captcha", "locked"))
            for r in respuestas
        )
        if not indicios_bloqueo:
            hallazgos.append(self.crear_hallazgo(
                titulo="No se observo rate limiting por IP ni CAPTCHA en el login",
                severidad=Severidad.MEDIA,
                evidencia=(
                    f"Tras {len(respuestas)} intento(s) de login invalidos, el endpoint "
                    f"{url} no mostro rate limiting por IP, respuesta 429/423 ni CAPTCHA "
                    f"(codigos observados: {codigos}). "
                    f"IMPORTANTE: la prueba usa usuarios aleatorios inexistentes y no ejecuta "
                    f"fuerza bruta, por lo que un bloqueo por cuenta (lockout sobre un usuario "
                    f"existente) NO es observable con este metodo y podria estar presente. "
                    f"Verifiquelo manualmente con una cuenta de prueba conocida."
                ),
                recomendacion=(
                    "Complemente el bloqueo por cuenta con rate limiting por IP y, si aplica, "
                    "CAPTCHA tras varios intentos fallidos, para mitigar ataques de fuerza "
                    "bruta distribuida y de relleno de credenciales."
                ),
                ubicacion=url,
            ))
        return hallazgos

    def _evaluar_enumeracion(self, respuestas, url):
        """Detecta mensajes de error que puedan revelar la existencia de usuarios."""
        hallazgos = []
        frases_reveladoras = (
            "usuario no existe", "user does not exist", "no such user",
            "contrasena incorrecta", "password incorrect", "invalid password",
            "el usuario no", "unknown user",
        )
        for r in respuestas:
            texto = r.text.lower()
            encontradas = [f for f in frases_reveladoras if f in texto]
            if encontradas:
                hallazgos.append(self.crear_hallazgo(
                    titulo="Posible enumeracion de usuarios por mensajes de error",
                    severidad=Severidad.MEDIA,
                    evidencia=(
                        f"La respuesta de login contiene mensajes que distinguen entre "
                        f"usuario y contrasena: {encontradas}. Esto permite deducir que "
                        f"usuarios existen."
                    ),
                    recomendacion=(
                        "Use un mensaje de error generico e identico para usuario "
                        "inexistente y contrasena incorrecta (por ejemplo, "
                        "'credenciales invalidas')."
                    ),
                    ubicacion=url,
                ))
                break
        return hallazgos

    def _evaluar_cookie_sesion(self, resp, url):
        """Revisa los atributos de seguridad de la cookie de sesion emitida."""
        hallazgos = []
        set_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
        es_https = url.lower().startswith("https://")
        for raw in set_cookies:
            nombre = raw.split("=", 1)[0].strip()
            attrs = raw.lower()
            faltantes = []
            if "httponly" not in attrs:
                faltantes.append("HttpOnly")
            if es_https and "secure" not in attrs:
                faltantes.append("Secure")
            if "samesite" not in attrs:
                faltantes.append("SameSite")
            if faltantes:
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Cookie de sesion con atributos inseguros: {nombre}",
                    severidad=Severidad.ALTA,
                    evidencia=f"La cookie de sesion '{nombre}' emitida en el login carece de: {', '.join(faltantes)}.",
                    recomendacion=(
                        "Configure la cookie de sesion con HttpOnly, Secure y SameSite para "
                        "protegerla frente a robo por XSS y ataques CSRF."
                    ),
                    ubicacion=url,
                ))
        return hallazgos
