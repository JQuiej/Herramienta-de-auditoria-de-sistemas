"""
Modulo hibrido: identificacion de tecnologias, versiones y servicios.

Cubre:
    RF-04   Identificar las tecnologias, versiones, puertos y servicios
            expuestos por el objetivo (la parte de puertos/servicios de red la
            cubre el modulo escaneo_puertos de la fase de herramientas integradas).
    Categoria OWASP: Software Supply Chain Failures / A06 Vulnerable Components.

Es "hibrido" (documento seccion 11.5.3): combina logica propia (analisis de
cabeceras, cookies y marcas en el HTML) con reconocimiento. Cuando detecta una
version concreta de un componente, lo marca como hallazgo para que pueda
cotejarse con CVE conocidos en la fase de herramientas integradas.
"""

from __future__ import annotations

import re

import requests

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo


# Firmas en cabeceras: nombre de cabecera -> etiqueta de tecnologia.
FIRMAS_CABECERAS = {
    "server": "Servidor web",
    "x-powered-by": "Framework/lenguaje",
    "x-aspnet-version": "ASP.NET",
    "x-generator": "Generador",
}

# Firmas por nombre de cookie -> tecnologia asociada.
FIRMAS_COOKIES = {
    "phpsessid": "PHP",
    "jsessionid": "Java (JSP/Servlets)",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel (PHP)",
    "csrftoken": "Django (Python)",
    "ci_session": "CodeIgniter (PHP)",
}

# Patron para extraer versiones (ej. "nginx/1.18.0", "PHP/7.4.3").
PATRON_VERSION = re.compile(r"([A-Za-z][\w\-\.]*?)[/ ](\d+\.\d+(?:\.\d+)?)")


@registrar_modulo
class Tecnologias(ModuloBase):
    nombre = "tecnologias"
    categoria_default = CategoriaOWASP.SUPPLY_CHAIN

    def run(self):
        hallazgos = []
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 30)), 30)

        try:
            resp = self.http.get(self.objetivo, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            self.logger.error("tecnologias: objetivo inaccesible: %s", exc)
            return hallazgos

        detectadas: dict[str, str] = {}  # tecnologia -> version (o "")

        # 1. Cabeceras.
        for cabecera, etiqueta in FIRMAS_CABECERAS.items():
            valor = resp.headers.get(cabecera)
            if valor:
                detectadas[f"{etiqueta}: {valor}"] = valor
                for nombre, version in PATRON_VERSION.findall(valor):
                    detectadas[nombre] = version

        # 2. Cookies.
        for cookie in resp.cookies:
            tech = FIRMAS_COOKIES.get(cookie.name.lower())
            if tech:
                detectadas.setdefault(tech, "")

        # 3. Marcas en el HTML (meta generator).
        meta = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
            resp.text, re.IGNORECASE,
        )
        if meta:
            detectadas[f"Generator: {meta.group(1)}"] = meta.group(1)
            for nombre, version in PATRON_VERSION.findall(meta.group(1)):
                detectadas[nombre] = version

        if not detectadas:
            self.logger.info("tecnologias: no se identificaron tecnologias por firmas.")
            return hallazgos

        # 4. Generar hallazgos.
        con_version = {t: v for t, v in detectadas.items() if re.match(r"^[\w\-\.]+$", t) and v}
        for tech, version in con_version.items():
            hallazgos.append(self.crear_hallazgo(
                titulo=f"Componente con version identificada: {tech} {version}",
                severidad=Severidad.MEDIA,
                categoria=CategoriaOWASP.VULNERABLE_COMPONENTS,
                evidencia=(
                    f"Se identifico '{tech}' version '{version}' en el objetivo. "
                    "Una version concreta permite cotejar CVE conocidos."
                ),
                recomendacion=(
                    f"Verifique que '{tech} {version}' este actualizado y sin vulnerabilidades "
                    "conocidas. Oculte los numeros de version en las respuestas del servidor."
                ),
                ubicacion=self.objetivo,
            ))

        # Resumen informativo de todo lo detectado.
        resumen = "; ".join(sorted(detectadas.keys()))
        hallazgos.append(self.crear_hallazgo(
            titulo="Tecnologias detectadas en el objetivo",
            severidad=Severidad.INFORMATIVA,
            evidencia=f"Firmas identificadas: {resumen}.",
            recomendacion=(
                "Minimice la informacion de tecnologia y version expuesta publicamente "
                "para dificultar la busqueda de exploits especificos."
            ),
            ubicacion=self.objetivo,
        ))

        self.logger.info("tecnologias: %d tecnologia(s) identificada(s).", len(detectadas))
        return hallazgos
