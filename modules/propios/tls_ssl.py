"""
Modulo propio: analisis de la configuracion TLS/SSL del objetivo.

Cubre:
    RF-07   Analizar la configuracion TLS/SSL del objetivo, incluyendo
            protocolos obsoletos y caducidad del certificado.
    Categoria OWASP: A02 - Cryptographic Failures.

Es un modulo "propio": abre conexiones TLS de solo lectura para leer el
certificado y comprobar que protocolos negocia el servidor. No es intrusivo.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.models import CategoriaOWASP, Severidad
from modules.base import ModuloBase
from core.registry import registrar_modulo

# Protocolos obsoletos que NO deberian estar habilitados.
PROTOCOLOS_OBSOLETOS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}


@registrar_modulo
class TlsSsl(ModuloBase):
    nombre = "tls_ssl"
    categoria_default = CategoriaOWASP.CRYPTO_FAILURES

    def _host_port(self):
        partes = urlparse(self.objetivo)
        host = partes.hostname
        port = partes.port or (443 if partes.scheme == "https" else 80)
        return host, port

    def run(self):
        hallazgos = []
        partes = urlparse(self.objetivo)

        if partes.scheme != "https":
            hallazgos.append(self.crear_hallazgo(
                titulo="El objetivo no utiliza HTTPS",
                severidad=Severidad.ALTA,
                evidencia=f"El objetivo {self.objetivo} usa el esquema '{partes.scheme}', sin cifrado TLS.",
                recomendacion="Habilite HTTPS con un certificado valido para cifrar todo el trafico.",
                ubicacion=self.objetivo,
            ))
            return hallazgos

        host, port = self._host_port()
        timeout = min(int(self.config.get("timeouts", {}).get("por_modulo_seg", 15)), 15)

        # 1. Leer el certificado con verificacion. Si la verificacion falla
        #    (certificado caducado, autofirmado u hostname incorrecto), eso es
        #    en si un hallazgo. Luego reintentamos sin verificar para poder
        #    inspeccionar los detalles del certificado igualmente.
        cert = None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
            self.logger.info("tls_ssl: protocolo negociado por defecto: %s", proto)
        except ssl.SSLCertVerificationError as exc:
            hallazgos.append(self.crear_hallazgo(
                titulo="Certificado TLS no valido",
                severidad=Severidad.ALTA,
                evidencia=f"La verificacion del certificado de {host}:{port} fallo: {exc.verify_message or exc}",
                recomendacion=(
                    "Instale un certificado valido, vigente, emitido por una CA de confianza "
                    "y cuyo nombre coincida con el dominio del objetivo."
                ),
                ubicacion=f"{host}:{port}",
            ))
            cert = self._leer_cert_sin_verificar(host, port, timeout)
        except Exception as exc:
            self.logger.error("tls_ssl: no se pudo establecer conexion TLS: %s", exc)
            return hallazgos

        # 2. Caducidad del certificado (si se pudo leer).
        not_after = (cert or {}).get("notAfter")
        if not_after:
            try:
                vence = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                dias = (vence - datetime.now(timezone.utc)).days
                if dias < 0:
                    hallazgos.append(self.crear_hallazgo(
                        titulo="Certificado TLS caducado",
                        severidad=Severidad.CRITICA,
                        evidencia=f"El certificado caduco el {not_after} (hace {-dias} dias).",
                        recomendacion="Renueve el certificado TLS de inmediato.",
                        ubicacion=f"{host}:{port}",
                    ))
                elif dias < 30:
                    hallazgos.append(self.crear_hallazgo(
                        titulo="Certificado TLS proximo a caducar",
                        severidad=Severidad.MEDIA,
                        evidencia=f"El certificado caduca el {not_after} (en {dias} dias).",
                        recomendacion="Programe la renovacion del certificado TLS antes de su caducidad.",
                        ubicacion=f"{host}:{port}",
                    ))
            except ValueError as exc:
                self.logger.warning("tls_ssl: no se pudo interpretar la fecha del certificado: %s", exc)

        # 3. Comprobar si acepta protocolos obsoletos (RF-07).
        for nombre_proto, version in PROTOCOLOS_OBSOLETOS.items():
            if self._acepta_protocolo(host, port, version, timeout):
                hallazgos.append(self.crear_hallazgo(
                    titulo=f"Protocolo obsoleto habilitado: {nombre_proto}",
                    severidad=Severidad.ALTA,
                    evidencia=f"El servidor {host}:{port} acepta conexiones mediante {nombre_proto}.",
                    recomendacion=(
                        f"Deshabilite {nombre_proto} en el servidor y permita unicamente "
                        "TLS 1.2 o superior."
                    ),
                    ubicacion=f"{host}:{port}",
                ))

        return hallazgos

    def _leer_cert_sin_verificar(self, host, port, timeout):
        """
        Lee el certificado sin verificarlo, para inspeccionar su fecha de
        caducidad aunque la verificacion haya fallado. Devuelve un dict con al
        menos 'notAfter', o None si no se pudo interpretar.
        """
        try:
            pem = ssl.get_server_certificate((host, port), timeout=timeout)
        except Exception as exc:
            self.logger.debug("tls_ssl: no se pudo obtener el certificado PEM: %s", exc)
            return None
        try:
            from cryptography import x509  # dependencia opcional
            cert = x509.load_pem_x509_certificate(pem.encode())
            venc = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
            return {"notAfter": venc}
        except Exception:
            self.logger.debug(
                "tls_ssl: 'cryptography' no disponible; se omite el detalle de caducidad."
            )
            return None

    def _acepta_protocolo(self, host, port, version, timeout) -> bool:
        """Intenta un handshake forzando una version concreta de TLS."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except (ssl.SSLError, OSError, ValueError):
            return False
