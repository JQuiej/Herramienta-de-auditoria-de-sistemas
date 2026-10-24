"""
Registro de actividad de la auditoria (RF-15).

Cada auditoria genera un log con los modulos ejecutados, sus resultados y los
errores ocurridos, permitiendo la trazabilidad exigida por el RNF-07.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"


def crear_logger(nombre_auditoria: str = "auditoria") -> logging.Logger:
    """
    Crea un logger que escribe simultaneamente a consola y a un archivo
    con marca de tiempo dentro de la carpeta logs/.
    """
    LOG_DIR.mkdir(exist_ok=True)
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta_log = LOG_DIR / f"{nombre_auditoria}_{marca}.log"

    logger = logging.getLogger(f"auditoria.{marca}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    if logger.handlers:  # evita handlers duplicados si se llama dos veces
        return logger

    formato = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    consola = logging.StreamHandler()
    consola.setLevel(logging.INFO)
    consola.setFormatter(formato)

    archivo = logging.FileHandler(ruta_log, encoding="utf-8")
    archivo.setLevel(logging.DEBUG)
    archivo.setFormatter(formato)

    logger.addHandler(consola)
    logger.addHandler(archivo)
    logger.info("Log de auditoria iniciado: %s", ruta_log)
    return logger
