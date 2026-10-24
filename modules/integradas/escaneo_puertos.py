"""
Modulo de herramienta integrada: escaneo de puertos con nmap.

Cubre:
    RF-04   Identificar puertos y servicios expuestos.
    Categoria OWASP: A05 - Security Misconfiguration.

Envuelve nmap con una configuracion conservadora (documento seccion 11.6.3):
    - Sin scripts agresivos ni deteccion intrusiva.
    - Limitado a los puertos mas comunes para acotar el tiempo.
    - Salida XML parseada al modelo de datos comun (Hallazgo).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from core.models import CategoriaOWASP, Severidad
from modules.integradas.base_herramienta import HerramientaExterna
from core.registry import registrar_modulo


# Puertos que se consideran de mayor riesgo si estan expuestos.
PUERTOS_SENSIBLES = {
    21: ("FTP", Severidad.ALTA, "Transferencia de archivos sin cifrar."),
    23: ("Telnet", Severidad.CRITICA, "Acceso remoto sin cifrar; debe deshabilitarse."),
    3306: ("MySQL", Severidad.ALTA, "Base de datos expuesta directamente."),
    5432: ("PostgreSQL", Severidad.ALTA, "Base de datos expuesta directamente."),
    3389: ("RDP", Severidad.ALTA, "Escritorio remoto expuesto a Internet."),
    445: ("SMB", Severidad.ALTA, "Comparticion de archivos expuesta."),
    27017: ("MongoDB", Severidad.ALTA, "Base de datos NoSQL expuesta."),
    6379: ("Redis", Severidad.ALTA, "Almacen de datos en memoria expuesto."),
}


@registrar_modulo
class EscaneoPuertos(HerramientaExterna):
    nombre = "escaneo_puertos"
    categoria_default = CategoriaOWASP.SECURITY_MISCONFIG
    binarios = ["nmap"]

    def run(self):
        binario = self.localizar_binario()
        if not binario:
            return self._binario_ausente()

        host = urlparse(self.objetivo).hostname
        if not host:
            self.logger.error("escaneo_puertos: no se pudo extraer el host del objetivo.")
            return []

        opciones = self.config.get("opciones", {}).get("escaneo_puertos", {})
        top_ports = str(opciones.get("top_ports", 100))

        # Comando conservador: sin ping (-Pn), top-ports, tiempo moderado (-T3),
        # deteccion de version ligera (-sV) y salida XML por stdout.
        comando = [
            binario, "-Pn", "-T3", "--top-ports", top_ports,
            "-sV", "--version-light", "-oX", "-", host,
        ]
        resultado = self.ejecutar_comando(comando, self.timeout())
        if resultado is None or not resultado.stdout:
            return []

        return self._parsear_xml(resultado.stdout, host)

    def _parsear_xml(self, xml_texto: str, host: str):
        """Traduce la salida XML de nmap a hallazgos."""
        hallazgos = []
        try:
            raiz = ET.fromstring(xml_texto)
        except ET.ParseError as exc:
            self.logger.error("escaneo_puertos: no se pudo parsear la salida de nmap: %s", exc)
            return hallazgos

        abiertos = []
        for port in raiz.iter("port"):
            estado = port.find("state")
            if estado is None or estado.get("state") != "open":
                continue
            num = int(port.get("portid"))
            servicio_el = port.find("service")
            servicio = servicio_el.get("name", "?") if servicio_el is not None else "?"
            version = ""
            if servicio_el is not None:
                version = " ".join(
                    filter(None, [servicio_el.get("product"), servicio_el.get("version")])
                )
            abiertos.append((num, servicio, version))

            if num in PUERTOS_SENSIBLES:
                etiqueta, severidad, desc = PUERTOS_SENSIBLES[num]
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Puerto sensible expuesto: {num}/{etiqueta}",
                    severidad=severidad,
                    evidencia=(
                        f"El puerto {num} ({servicio} {version}) esta abierto en {host}. {desc}"
                    ),
                    recomendacion=(
                        f"Restrinja el acceso al puerto {num} mediante firewall; expongalo "
                        "solo a las redes estrictamente necesarias o cierrelo si no se usa."
                    ),
                    ubicacion=f"{host}:{num}",
                ))

        # Hallazgo informativo con el resumen de puertos abiertos.
        if abiertos:
            resumen = ", ".join(f"{n}/{s}" for n, s, _ in abiertos)
            hallazgos.append(self.crear_hallazgo(
                titulo=f"Puertos abiertos detectados ({len(abiertos)})",
                severidad=Severidad.INFORMATIVA,
                evidencia=f"nmap encontro los siguientes puertos abiertos en {host}: {resumen}.",
                recomendacion=(
                    "Revise que cada puerto abierto corresponda a un servicio necesario y "
                    "correctamente asegurado; cierre los que no se utilicen."
                ),
                ubicacion=host,
            ))
            self.logger.info("escaneo_puertos: %d puerto(s) abierto(s) en %s.", len(abiertos), host)

        return hallazgos
