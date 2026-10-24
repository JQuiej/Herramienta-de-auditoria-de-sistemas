"""Paquete de modulos de deteccion.

Al importar este paquete se registran automaticamente todos los modulos
disponibles, de modo que el orquestador pueda encontrarlos en el registro.
"""

# Modulos propios (peticiones HTTP directas, sin riesgo para el objetivo).
from modules.propios import cabeceras_http  # noqa: F401
from modules.propios import cookies  # noqa: F401
from modules.propios import tls_ssl  # noqa: F401
from modules.propios import archivos_expuestos  # noqa: F401

# Modulos semiautomaticos (reconocimiento + logica propia).
from modules.semiautomaticos import crawler  # noqa: F401
from modules.semiautomaticos import crawler_js  # noqa: F401
from modules.semiautomaticos import tecnologias  # noqa: F401
from modules.semiautomaticos import metodos_http  # noqa: F401
from modules.semiautomaticos import autenticacion  # noqa: F401

# Herramientas integradas (envuelven binarios externos; se omiten si faltan).
from modules.integradas import escaneo_puertos  # noqa: F401
from modules.integradas import plantillas_cve  # noqa: F401
from modules.integradas import inyeccion_sql  # noqa: F401
from modules.integradas import escaneo_activo_xss  # noqa: F401
