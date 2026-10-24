"""
Interfaz de linea de comandos de la herramienta de auditoria (capa de interfaz).

Coordina el flujo del caso de uso "Ejecutar auditoria":
    1. Carga y valida la configuracion (RF-01, RF-03, flujo A1).
    2. Confirma la autorizacion (RF-02, RNF-03, flujo A2).
    3. Ejecuta el orquestador (Diagrama de flujo 1).
    4. Muestra un resumen final de la auditoria.

Uso:
    python main.py                      # usa config.yaml
    python main.py -c otra_config.yaml
    python main.py --autorizar          # confirma autorizacion por CLI
    python main.py --listar-modulos     # muestra los modulos registrados

Nota: la generacion de reportes (RF-14) y el motor de riesgo (RF-12/13) se
implementan en fases posteriores; esta fase deja el nucleo funcionando y un
resumen de hallazgos por consola.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

# Importar el paquete de modulos registra todos los modulos disponibles.
import modules  # noqa: F401
from core.config_loader import ConfigError, cargar_config
from core.logger import crear_logger
from core.orchestrator import AutorizacionError, Orquestador
from core.registry import modulos_registrados
from core.models import Severidad
from riesgo.motor_riesgo import MotorRiesgo
from reportes.generador import GeneradorReportes


ORDEN_SEVERIDAD = [
    Severidad.CRITICA,
    Severidad.ALTA,
    Severidad.MEDIA,
    Severidad.BAJA,
    Severidad.INFORMATIVA,
]


def listar_modulos() -> None:
    """Muestra los modulos actualmente registrados en el sistema."""
    registrados = modulos_registrados()
    print("\nModulos de deteccion registrados:")
    if not registrados:
        print("  (ninguno)")
        return
    for nombre, clase in sorted(registrados.items()):
        categoria = clase.categoria_default.value
        print(f"  - {nombre:<20} {categoria}")
    print()


def imprimir_resumen(hallazgos) -> None:
    """Resumen final de la auditoria por consola (paso 6 del caso de uso)."""
    print("\n" + "=" * 68)
    print("  RESUMEN DE LA AUDITORIA")
    print("=" * 68)

    if not hallazgos:
        print("  No se generaron hallazgos.")
        print("=" * 68 + "\n")
        return

    conteo = Counter(h.severidad for h in hallazgos)
    for sev in ORDEN_SEVERIDAD:
        if conteo.get(sev):
            print(f"  {sev.value:<14}: {conteo[sev]}")
    print("-" * 68)
    print(f"  Total de hallazgos: {len(hallazgos)}")
    print("=" * 68)

    print("\n  Detalle:")
    for h in sorted(hallazgos, key=lambda x: ORDEN_SEVERIDAD.index(x.severidad)):
        print(f"\n  [{h.severidad.value}] {h.titulo or h.categoria.value}")
        print(f"     Categoria : {h.categoria.value}")
        print(f"     Modulo    : {h.modulo_origen}")
        if h.ubicacion:
            print(f"     Ubicacion : {h.ubicacion}")
        print(f"     Evidencia : {h.evidencia}")
    print()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Herramienta de auditoria de seguridad automatizada "
        "(Cooperativa Nuevo Amanecer, R.L.)."
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml",
        help="Ruta al archivo de configuracion (por defecto: config.yaml).",
    )
    parser.add_argument(
        "--autorizar", action="store_true",
        help="Confirma la autorizacion para auditar (equivale a autorizado: true).",
    )
    parser.add_argument(
        "--listar-modulos", action="store_true",
        help="Lista los modulos de deteccion registrados y termina.",
    )
    args = parser.parse_args(argv)

    if args.listar_modulos:
        listar_modulos()
        return 0

    # 1. Cargar y validar configuracion (RF-01, RF-03, flujo A1).
    try:
        config = cargar_config(args.config)
    except ConfigError as exc:
        print(f"[ERROR de configuracion] {exc}", file=sys.stderr)
        return 2

    # La autorizacion puede confirmarse por CLI o en el archivo (RF-02).
    if args.autorizar:
        config.autorizado = True

    logger = crear_logger(config.nombre.replace(" ", "_"))
    logger.info("Configuracion cargada desde: %s", config.ruta)
    logger.info("Objetivo: %s (%s)", config.url, config.nombre)

    # 2-3. Ejecutar la auditoria (RF-02 gate + Diagrama de flujo 1).
    orquestador = Orquestador(config, logger)
    try:
        hallazgos = orquestador.ejecutar()
    except AutorizacionError as exc:
        print(f"\n[AUDITORIA BLOQUEADA] {exc}", file=sys.stderr)
        print(
            "Confirme la autorizacion con --autorizar o 'autorizado: true' en "
            "config.yaml, solo si cuenta con permiso explicito.",
            file=sys.stderr,
        )
        return 3

    # 4. Motor de analisis de riesgos (RF-12, RF-13): enriquece cada hallazgo
    #    con impacto, probabilidad, nivel de riesgo y CVSS, y agrega el resumen.
    logger.info("Ejecutando motor de analisis de riesgos...")
    motor = MotorRiesgo()
    resumen_riesgo = motor.procesar(hallazgos)
    logger.info(
        "Riesgo promedio: %.1f | Criticos: %d | Altos: %d",
        resumen_riesgo.riesgo_promedio,
        resumen_riesgo.por_nivel.get("Critico", 0),
        resumen_riesgo.por_nivel.get("Alto", 0),
    )

    # 5. Generacion del informe (RF-14): JSON, HTML y PDF.
    generador = GeneradorReportes(logger=logger)
    meta = {"url": config.url, "nombre_objetivo": config.nombre}
    rutas = generador.generar(hallazgos, resumen_riesgo, meta)

    # 6. Resumen final por consola.
    imprimir_resumen(hallazgos)
    print("  Informes generados:")
    for fmt, ruta in rutas.items():
        estado = str(ruta) if ruta else "(no generado)"
        print(f"    {fmt.upper():<5}: {estado}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
