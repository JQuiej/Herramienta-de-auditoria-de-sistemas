"""
Metadatos de los modulos para la interfaz web.

Proporciona, para cada modulo registrado: su tipo, categoria OWASP, una
descripcion legible y (para las herramientas integradas) si el binario externo
esta disponible. Tambien define el ORDEN de ejecucion recomendado y los
PERFILES de escaneo predefinidos, para que la configuracion sea de un clic.
"""

from __future__ import annotations

import shutil

from core.registry import modulos_registrados

# Descripciones legibles por modulo (RNF-06: lenguaje claro, sin jerga).
DESCRIPCIONES = {
    "cabeceras_http": "Revisa cabeceras HTTP de seguridad ausentes o mal configuradas.",
    "cookies": "Verifica los atributos Secure, HttpOnly y SameSite de las cookies.",
    "tls_ssl": "Analiza el certificado y los protocolos TLS/SSL del objetivo.",
    "archivos_expuestos": "Busca archivos y directorios sensibles accesibles publicamente.",
    "crawler": "Rastrea el sitio y descubre rutas, formularios y parametros de entrada.",
    "crawler_js": "Rastrea ejecutando JavaScript (SPA); descubre rutas, formularios y endpoints de API.",
    "tecnologias": "Identifica tecnologias, frameworks y versiones expuestas.",
    "metodos_http": "Detecta metodos HTTP peligrosos y posible path traversal.",
    "autenticacion": "Evalua controles de login sin fuerza bruta (limite de intentos, cookie de sesion).",
    "escaneo_puertos": "Escanea puertos y servicios expuestos con nmap.",
    "plantillas_cve": "Busca vulnerabilidades conocidas por plantillas de CVE con nuclei.",
    "inyeccion_sql": "Detecta inyeccion SQL en parametros con sqlmap (modo conservador).",
    "escaneo_activo_xss": "Detecta Cross-Site Scripting (XSS) con dalfox.",
}

# Orden de ejecucion: el crawler antes que los modulos que consumen su contexto.
ORDEN_MODULOS = [
    "cabeceras_http", "cookies", "tls_ssl", "archivos_expuestos",
    "crawler", "crawler_js", "tecnologias", "metodos_http",
    "escaneo_puertos", "plantillas_cve",
    "autenticacion", "inyeccion_sql", "escaneo_activo_xss",
]

# Etiquetas legibles de tipo segun el paquete del modulo.
_TIPOS = {
    "propios": "Propio",
    "semiautomaticos": "Semiautomatico",
    "integradas": "Herramienta integrada",
}

# Perfiles de escaneo predefinidos (configuracion de un clic).
PERFILES = {
    "rapido": {
        "nombre": "Escaneo rapido (pasivo)",
        "descripcion": "Solo verificaciones propias, sin enviar cargas. Rapido y seguro.",
        "modulos": ["cabeceras_http", "cookies", "tls_ssl", "archivos_expuestos", "tecnologias"],
    },
    "completo": {
        "nombre": "Escaneo completo",
        "descripcion": "Todos los modulos aplicables, incluidas herramientas integradas disponibles.",
        "modulos": ORDEN_MODULOS,
    },
    "autenticacion": {
        "nombre": "Solo autenticacion",
        "descripcion": "Rastrea el sitio y evalua los controles del login (sin fuerza bruta).",
        "modulos": ["crawler", "autenticacion"],
    },
    "spa": {
        "nombre": "App moderna (SPA/JS)",
        "descripcion": "Usa navegador headless para apps React/Vue/Angular y descubre su API.",
        "modulos": ["cabeceras_http", "cookies", "tls_ssl", "crawler_js",
                    "tecnologias", "metodos_http", "autenticacion"],
    },
}


def _tipo_modulo(clase) -> str:
    modulo_py = clase.__module__  # p.ej. 'modules.propios.cabeceras_http'
    for clave, etiqueta in _TIPOS.items():
        if f".{clave}." in modulo_py:
            return etiqueta
    return "Otro"


def listar_modulos() -> list[dict]:
    """Devuelve metadatos de todos los modulos, en el orden de ejecucion."""
    registrados = modulos_registrados()
    resultado = []
    for nombre in ORDEN_MODULOS:
        clase = registrados.get(nombre)
        if clase is None:
            continue
        binarios = getattr(clase, "binarios", [])
        disponible = True
        binario_necesario = None
        # Modulos con chequeo propio de disponibilidad (p.ej. crawler_js/Playwright).
        if hasattr(clase, "esta_disponible"):
            try:
                disponible = clase.esta_disponible()
            except Exception:
                disponible = False
            binario_necesario = getattr(clase, "requiere_etiqueta", None)
        elif binarios:
            binario_necesario = binarios[0]
            disponible = any(shutil.which(b) for b in binarios)
        resultado.append({
            "nombre": nombre,
            "tipo": _tipo_modulo(clase),
            "categoria": clase.categoria_default.value,
            "descripcion": DESCRIPCIONES.get(nombre, ""),
            "requiere_binario": binario_necesario,
            "disponible": disponible,
        })
    # Anexar cualquier modulo registrado que no este en ORDEN_MODULOS.
    for nombre, clase in registrados.items():
        if nombre not in ORDEN_MODULOS:
            resultado.append({
                "nombre": nombre, "tipo": _tipo_modulo(clase),
                "categoria": clase.categoria_default.value,
                "descripcion": DESCRIPCIONES.get(nombre, ""),
                "requiere_binario": None, "disponible": True,
            })
    return resultado
