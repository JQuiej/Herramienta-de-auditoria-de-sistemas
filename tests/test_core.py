"""
Pruebas unitarias del nucleo (Fase 1).

Ejecutar con:  python -m pytest -q     (o)   python -m unittest -v
Estas pruebas no tocan ningun objetivo de red: validan la logica del core.
"""

import unittest

from core.config_loader import Configuracion, ConfigError, validar_url
from core.logger import crear_logger
from core.models import CategoriaOWASP, Hallazgo, Severidad
from core.orchestrator import AutorizacionError, Orquestador


class TestValidacionURL(unittest.TestCase):
    def test_url_valida(self):
        self.assertEqual(validar_url("https://sag.local"), "https://sag.local")

    def test_url_sin_esquema_falla(self):  # flujo A1
        with self.assertRaises(ConfigError):
            validar_url("example.com")

    def test_url_esquema_no_http_falla(self):  # flujo A1
        with self.assertRaises(ConfigError):
            validar_url("ftp://x.com")


class TestHallazgo(unittest.TestCase):
    def test_serializacion(self):
        h = Hallazgo(
            categoria=CategoriaOWASP.INJECTION,
            severidad=Severidad.CRITICA,
            evidencia="payload confirmado",
            recomendacion="parametrizar consultas",
            modulo_origen="inyeccion_sql",
        )
        d = h.to_dict()
        self.assertEqual(d["categoria"], "A03 - Injection")
        self.assertEqual(d["severidad"], "Critica")
        self.assertTrue(d["id"])
        self.assertTrue(d["timestamp"])


class TestGateAutorizacion(unittest.TestCase):
    """RF-02: la auditoria debe bloquearse sin autorizacion confirmada."""

    def _config(self, autorizado):
        return Configuracion(
            url="https://sag.local", nombre="test", autorizado=autorizado,
            modulos={}, timeouts={},
        )

    def test_bloquea_sin_autorizacion(self):
        logger = crear_logger("test_gate")
        orq = Orquestador(self._config(False), logger)
        with self.assertRaises(AutorizacionError):
            orq.ejecutar()

    def test_permite_con_autorizacion(self):
        logger = crear_logger("test_gate")
        orq = Orquestador(self._config(True), logger)
        # Sin modulos activos devuelve lista vacia, pero no lanza excepcion.
        self.assertEqual(orq.ejecutar(), [])


class _FakeResp:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content


class TestLineaBase(unittest.TestCase):
    """RNF-04: el patron de linea base evita falsos positivos."""

    def setUp(self):
        from modules.propios.archivos_expuestos import ArchivosExpuestos
        self.es_real = ArchivosExpuestos._es_exposicion_real

    def test_servidor_permisivo_no_reporta(self):
        # Ruta responde igual que la linea base (200) -> NO es exposicion real.
        base_status, base_len = 200, 1000
        resp = _FakeResp(200, b"x" * 1000)
        self.assertFalse(self.es_real(resp, base_status, base_len))

    def test_exposicion_real_se_reporta(self):
        # Linea base 404, pero la ruta sensible responde 200 con otro contenido.
        base_status, base_len = 404, 559
        resp = _FakeResp(200, b"[core]\nrepositoryformatversion = 0\n")
        self.assertTrue(self.es_real(resp, base_status, base_len))

    def test_404_nunca_es_exposicion(self):
        resp = _FakeResp(404, b"not found")
        self.assertFalse(self.es_real(resp, 404, 9))


class TestMotorRiesgo(unittest.TestCase):
    """RF-12/RF-13: motor de analisis de riesgos (seccion 5)."""

    def setUp(self):
        from riesgo.motor_riesgo import MotorRiesgo, nivel_riesgo
        self.motor = MotorRiesgo()
        self.nivel = nivel_riesgo

    def test_clasificacion_niveles(self):  # seccion 5.3
        self.assertEqual(self.nivel(4), "Bajo")
        self.assertEqual(self.nivel(8), "Medio")
        self.assertEqual(self.nivel(12), "Alto")
        self.assertEqual(self.nivel(20), "Critico")

    def test_enriquece_hallazgo(self):
        h = Hallazgo(
            categoria=CategoriaOWASP.INJECTION, severidad=Severidad.CRITICA,
            evidencia="e", recomendacion="r", modulo_origen="m",
        )
        resumen = self.motor.procesar([h])
        # Injection -> impacto 5; Critica -> probabilidad 5; riesgo 25 -> Critico.
        self.assertEqual(h.impacto, 5)
        self.assertEqual(h.probabilidad, 5)
        self.assertEqual(h.nivel_riesgo, "Critico")
        self.assertEqual(h.cvss, 9.5)  # estimado desde severidad
        self.assertEqual(resumen.total, 1)
        self.assertEqual(resumen.por_nivel["Critico"], 1)
        self.assertEqual(resumen.mapa_calor[5][5], 1)

    def test_respeta_cvss_provisto(self):
        h = Hallazgo(
            categoria=CategoriaOWASP.SECURITY_MISCONFIG, severidad=Severidad.MEDIA,
            evidencia="e", recomendacion="r", modulo_origen="m", cvss=6.6,
        )
        self.motor.procesar([h])
        self.assertEqual(h.cvss, 6.6)  # no se sobrescribe si ya venia


class TestGeneradorReportes(unittest.TestCase):
    """RF-14: generacion de informe JSON, PDF y Excel."""

    def test_genera_json_pdf_excel(self):
        import json
        import tempfile
        from riesgo.motor_riesgo import MotorRiesgo
        from reportes.generador import GeneradorReportes

        h = Hallazgo(
            categoria=CategoriaOWASP.INJECTION, severidad=Severidad.ALTA,
            evidencia="payload", recomendacion="parametrizar", modulo_origen="inyeccion_sql",
            titulo="Posible inyeccion SQL",
        )
        resumen = MotorRiesgo().procesar([h])
        with tempfile.TemporaryDirectory() as d:
            gen = GeneradorReportes(directorio_salida=d)
            rutas = gen.generar([h], resumen, {"url": "http://x", "nombre_objetivo": "t"})
            # JSON siempre; PDF y Excel presentes con las librerias instaladas.
            self.assertTrue(rutas["json"].exists())
            datos = json.loads(rutas["json"].read_text(encoding="utf-8"))
            self.assertEqual(datos["metadata"]["total_hallazgos"], 1)
            self.assertIn("resumen_riesgo", datos)
            self.assertTrue(rutas["pdf"].exists())
            self.assertGreater(rutas["pdf"].stat().st_size, 0)
            self.assertTrue(rutas["excel"].exists())
            self.assertGreater(rutas["excel"].stat().st_size, 0)


class TestHerramientasIntegradas(unittest.TestCase):
    """Fase 5: validacion del parseo de salidas de herramientas externas."""

    def setUp(self):
        import logging
        self.lg = logging.getLogger("t_int")
        self.lg.addHandler(logging.NullHandler())
        self.cfg = {"timeouts": {"por_modulo_seg": 10}}

    def test_nmap_xml(self):
        from modules.integradas.escaneo_puertos import EscaneoPuertos
        xml = ('<nmaprun><host><ports>'
               '<port portid="23"><state state="open"/><service name="telnet"/></port>'
               '<port portid="80"><state state="open"/><service name="http"/></port>'
               '</ports></host></nmaprun>')
        hs = EscaneoPuertos("http://h", self.cfg, self.lg)._parsear_xml(xml, "h")
        titulos = [h.titulo for h in hs]
        self.assertTrue(any("23/Telnet" in t for t in titulos))
        self.assertTrue(any("Puertos abiertos" in t for t in titulos))

    def test_nuclei_jsonl(self):
        import json
        from modules.integradas.plantillas_cve import PlantillasCVE
        jl = json.dumps({"template-id": "CVE-2021-44228",
                         "info": {"name": "Log4j", "severity": "critical"},
                         "matched-at": "http://h/api"})
        hs = PlantillasCVE("http://h", self.cfg, self.lg)._parsear_jsonl(jl)
        self.assertEqual(len(hs), 1)
        self.assertEqual(hs[0].severidad, Severidad.CRITICA)

    def test_sqlmap_vulnerable(self):
        from modules.integradas.inyeccion_sql import InyeccionSQL
        out = "sqlmap identified the following injection point\nParameter: id (GET)"
        hs = InyeccionSQL("http://h", self.cfg, self.lg)._parsear_salida(out, "http://h?id=1")
        self.assertEqual(len(hs), 1)
        self.assertEqual(hs[0].categoria, CategoriaOWASP.INJECTION)

    def test_sqlmap_no_vulnerable(self):
        from modules.integradas.inyeccion_sql import InyeccionSQL
        hs = InyeccionSQL("http://h", self.cfg, self.lg)._parsear_salida("all tested, none", "http://h?id=1")
        self.assertEqual(hs, [])

    def test_dalfox_xss(self):
        import json
        from modules.integradas.escaneo_activo_xss import EscaneoActivoXSS
        dj = json.dumps([{"type": "V", "method": "GET", "param": "q", "data": "<script>"}])
        hs = EscaneoActivoXSS("http://h", self.cfg, self.lg)._parsear_salida(dj, "http://h?q=1")
        self.assertEqual(len(hs), 1)

    def test_binario_ausente_no_crashea(self):
        from modules.integradas.escaneo_puertos import EscaneoPuertos
        # Con binario ausente, run() devuelve [] sin excepcion (RNF-02).
        m = EscaneoPuertos("http://h", self.cfg, self.lg)
        m.binarios = ["binario_que_no_existe_xyz"]
        self.assertEqual(m.run(), [])


class TestEscaneoAutenticado(unittest.TestCase):
    """Mejora #1: la sesion de login se propaga a los modulos (self.http)."""

    def test_http_aplica_cookies_y_headers(self):
        from modules.propios.cabeceras_http import CabecerasHTTP
        cfg = {
            "timeouts": {"por_modulo_seg": 10},
            "auth": {
                "cookies": {"SESSION": "valido123"},
                "headers": {"Authorization": "Bearer abc.def.ghi"},
            },
        }
        import logging
        lg = logging.getLogger("t_auth"); lg.addHandler(logging.NullHandler())
        m = CabecerasHTTP("http://h", cfg, lg)
        s = m.http  # construye la sesion con la autenticacion
        self.assertEqual(s.cookies.get("SESSION"), "valido123")
        self.assertEqual(s.headers.get("Authorization"), "Bearer abc.def.ghi")

    def test_sin_auth_sesion_limpia(self):
        from modules.propios.cabeceras_http import CabecerasHTTP
        import logging
        lg = logging.getLogger("t_auth2"); lg.addHandler(logging.NullHandler())
        m = CabecerasHTTP("http://h", {"timeouts": {}}, lg)
        self.assertNotIn("Authorization", m.http.headers)

    def test_autenticar_login_incompleto(self):
        from core.autenticador import autenticar
        import logging
        lg = logging.getLogger("t_auth3"); lg.addHandler(logging.NullHandler())
        r = autenticar({"url": "http://h", "usuario": "", "password": ""}, lg)
        self.assertFalse(r["exito"])


if __name__ == "__main__":
    unittest.main()
