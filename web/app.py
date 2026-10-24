"""
Aplicacion web de la herramienta de auditoria (FastAPI).

Expone una interfaz web para configurar y ejecutar la auditoria sin editar
archivos a mano, con progreso en vivo (Server-Sent Events) y descarga del
informe. El stack (Python + FastAPI + HTML/JavaScript) es el previsto en la
documentacion del proyecto.

Ejecutar:
    python -m web.app
    (o)  uvicorn web.app:app --reload
Luego abrir http://127.0.0.1:8000
"""

from __future__ import annotations

import json
import queue
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Importar el paquete de modulos registra todos los modulos disponibles.
import modules  # noqa: F401
from core.config_loader import Configuracion, validar_url, ConfigError
from core.logger import crear_logger
from core.orchestrator import AutorizacionError, Orquestador
from reportes.generador import GeneradorReportes
from riesgo.motor_riesgo import MotorRiesgo
from web.metadata import ORDEN_MODULOS, PERFILES, listar_modulos

BASE_DIR = Path(__file__).resolve().parent
app = FastAPI(title="Herramienta de Auditoria de Seguridad")

# Estado en memoria de las auditorias en curso o finalizadas.
_auditorias: dict[str, dict] = {}


# --------------------------------------------------------------- modelos API
class OpcionesAvanzadas(BaseModel):
    crawler_max_paginas: int = 25
    login_url: str | None = None
    login_campo_usuario: str = "username"
    login_campo_password: str = "password"
    login_max_intentos: int = 4
    timeout_por_modulo: int = 120
    # Escaneo autenticado: credenciales usadas solo para iniciar sesion.
    autenticar: bool = False
    login_usuario: str | None = None
    login_password: str | None = None


class ConfigAuditoria(BaseModel):
    url: str
    nombre: str = "Auditoria"
    autorizado: bool = False
    modulos: dict[str, bool]
    opciones: OpcionesAvanzadas = OpcionesAvanzadas()


# --------------------------------------------------------------- utilidades
def _construir_configuracion(cfg: ConfigAuditoria) -> Configuracion:
    """Traduce la peticion web a un objeto Configuracion, en orden de ejecucion."""
    # Ordenar los modulos activos segun ORDEN_MODULOS (crawler antes de inyeccion).
    modulos_ordenados = {}
    for nombre in ORDEN_MODULOS:
        if cfg.modulos.get(nombre):
            modulos_ordenados[nombre] = True
    for nombre, activo in cfg.modulos.items():  # cualquier extra no listado
        if activo and nombre not in modulos_ordenados:
            modulos_ordenados[nombre] = True

    op = cfg.opciones
    opciones = {
        "crawler": {"max_paginas": op.crawler_max_paginas},
        "autenticacion": {
            "campo_usuario": op.login_campo_usuario,
            "campo_password": op.login_campo_password,
            "max_intentos": op.login_max_intentos,
        },
    }
    if op.login_url:
        opciones["autenticacion"]["url_login"] = op.login_url

    # Escaneo autenticado: si se piden credenciales, configurar el login previo.
    if op.autenticar and op.login_usuario and op.login_password:
        opciones["login"] = {
            "realizar": True,
            "url": op.login_url or cfg.url,
            "usuario": op.login_usuario,
            "password": op.login_password,
            "campo_usuario": op.login_campo_usuario,
            "campo_password": op.login_campo_password,
            "modo": "auto",
        }

    return Configuracion(
        url=cfg.url,
        nombre=cfg.nombre or "Auditoria",
        autorizado=cfg.autorizado,
        modulos=modulos_ordenados,
        timeouts={"por_modulo_seg": op.timeout_por_modulo},
        opciones=opciones,
    )


def _worker(audit_id: str, config: Configuracion):
    """Hilo de trabajo: ejecuta la auditoria y publica eventos en la cola."""
    estado = _auditorias[audit_id]
    cola: queue.Queue = estado["cola"]
    logger = crear_logger(config.nombre.replace(" ", "_"))
    try:
        orq = Orquestador(config, logger, listener=cola.put)
        hallazgos = orq.ejecutar()

        resumen = MotorRiesgo().procesar(hallazgos)
        meta = {"url": config.url, "nombre_objetivo": config.nombre}
        rutas = GeneradorReportes(logger=logger).generar(hallazgos, resumen, meta)

        estado["hallazgos"] = hallazgos
        estado["resumen"] = resumen
        estado["rutas"] = rutas
        # Se guardan config, contexto y meta para que la pestaña de IA pueda
        # analizar los hallazgos y orquestar pruebas adicionales reutilizandolos.
        estado["config"] = config
        estado["contexto"] = orq.contexto
        estado["meta"] = meta
        estado["estado"] = "finalizado"
        cola.put({
            "tipo": "completado",
            "resumen": resumen.to_dict(),
            "hallazgos": [_hallazgo_dict(h) for h in _ordenar(hallazgos)],
            "pdf_disponible": bool(rutas.get("pdf")),
            "excel_disponible": bool(rutas.get("excel")),
        })
    except AutorizacionError as exc:
        estado["estado"] = "error"
        cola.put({"tipo": "abortado", "error": str(exc)})
    except Exception as exc:
        estado["estado"] = "error"
        cola.put({"tipo": "abortado", "error": f"Error inesperado: {exc}"})


def _ordenar(hallazgos):
    orden = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Informativa": 4}
    return sorted(hallazgos, key=lambda h: orden.get(h.severidad.value, 9))


def _hallazgo_dict(h) -> dict:
    return {
        "severidad": h.severidad.value,
        "titulo": h.titulo or h.categoria.value,
        "categoria": h.categoria.value,
        "modulo": h.modulo_origen,
        "cvss": h.cvss,
        "nivel_riesgo": h.nivel_riesgo,
        "ubicacion": h.ubicacion,
        "evidencia": h.evidencia,
        "recomendacion": h.recomendacion,
    }


# ------------------------------------------------------------------- rutas
@app.get("/", response_class=HTMLResponse)
def indice():
    return (BASE_DIR / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/modulos")
def api_modulos():
    return {"modulos": listar_modulos(), "perfiles": PERFILES}


@app.post("/api/auditoria/iniciar")
def api_iniciar(cfg: ConfigAuditoria):
    # Validaciones (flujos A1 y A2 del caso de uso "Configurar auditoria").
    try:
        cfg.url = validar_url(cfg.url)
    except ConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not cfg.autorizado:
        raise HTTPException(
            status_code=403,
            detail="Debe confirmar la autorizacion para auditar el objetivo (RF-02).",
        )
    if not any(cfg.modulos.values()):
        raise HTTPException(status_code=400, detail="Seleccione al menos un modulo.")

    audit_id = uuid.uuid4().hex[:12]
    _auditorias[audit_id] = {"cola": queue.Queue(), "estado": "ejecutando", "rutas": {}}

    config = _construir_configuracion(cfg)
    threading.Thread(target=_worker, args=(audit_id, config), daemon=True).start()
    return {"audit_id": audit_id}


@app.get("/api/auditoria/{audit_id}/eventos")
def api_eventos(audit_id: str):
    estado = _auditorias.get(audit_id)
    if estado is None:
        raise HTTPException(status_code=404, detail="Auditoria no encontrada.")

    def generar():
        cola: queue.Queue = estado["cola"]
        while True:
            try:
                evento = cola.get(timeout=30)
            except queue.Empty:
                yield ": keep-alive\n\n"  # comentario SSE para mantener viva la conexion
                continue
            yield f"data: {json.dumps(evento, ensure_ascii=False)}\n\n"
            if evento.get("tipo") in ("completado", "abortado"):
                break

    return StreamingResponse(generar(), media_type="text/event-stream")


@app.get("/api/auditoria/{audit_id}/informe.{formato}")
def api_informe(audit_id: str, formato: str):
    estado = _auditorias.get(audit_id)
    if estado is None or estado.get("estado") != "finalizado":
        raise HTTPException(status_code=404, detail="Informe no disponible.")
    ruta = estado.get("rutas", {}).get(formato)
    if not ruta or not Path(ruta).exists():
        raise HTTPException(status_code=404, detail=f"No hay informe en formato {formato}.")
    tipos = {
        "json": "application/json",
        "pdf": "application/pdf",
        "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    # Descargar con el nombre real del archivo (con su extension .pdf / .xlsx).
    return FileResponse(
        str(ruta),
        media_type=tipos.get(formato, "application/octet-stream"),
        filename=Path(ruta).name,
    )


# --------------------------------------------------------------- IA (Gemini)
class PeticionIA(BaseModel):
    audit_id: str
    api_key: str | None = None     # opcional: si no, se usa GEMINI_API_KEY del entorno
    modelo: str | None = None      # opcional: si no, GEMINI_MODEL o el valor por defecto


def _estado_finalizado(audit_id: str) -> dict:
    estado = _auditorias.get(audit_id)
    if estado is None or estado.get("estado") != "finalizado":
        raise HTTPException(status_code=404, detail="No hay una auditoria finalizada con ese id. "
                                                    "Ejecute primero una auditoria en la pestaña Auditoria.")
    return estado


@app.post("/api/ia/analizar")
def api_ia_analizar(pet: PeticionIA):
    """La IA analiza los hallazgos ya detectados (no ejecuta nada)."""
    from core.ia_gemini import GeminiCliente, IAError, analizar_hallazgos
    estado = _estado_finalizado(pet.audit_id)
    logger = crear_logger("ia_analisis")
    try:
        cliente = GeminiCliente(api_key=pet.api_key, modelo=pet.modelo, logger=logger)
        analisis = analizar_hallazgos(cliente, estado["hallazgos"], estado["resumen"], estado["meta"])
    except IAError as exc:
        logger.error("IA (analizar) fallo: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))
    # Generar el PDF del analisis para descarga.
    try:
        from reportes.generador_ia import generar_pdf_analisis
        estado["ia_analisis_pdf"] = generar_pdf_analisis(analisis, estado["meta"], logger)
    except Exception as exc:
        logger.error("No se pudo generar el PDF del analisis: %s", exc)
        estado["ia_analisis_pdf"] = None
    return {"analisis": analisis, "pdf": bool(estado.get("ia_analisis_pdf"))}


@app.get("/api/ia/{audit_id}/analisis.pdf")
def api_ia_analisis_pdf(audit_id: str):
    estado = _auditorias.get(audit_id) or {}
    ruta = estado.get("ia_analisis_pdf")
    if not ruta or not Path(ruta).exists():
        raise HTTPException(status_code=404, detail="No hay PDF de analisis disponible.")
    return FileResponse(str(ruta), media_type="application/pdf", filename=Path(ruta).name)


@app.post("/api/ia/orquestar")
def api_ia_orquestar(pet: PeticionIA):
    """
    La IA PROPONE pruebas no destructivas; el codigo las valida contra la lista
    blanca (solo modulos existentes) y las ejecuta reutilizando el contexto y la
    autorizacion ya confirmada. Luego la IA emite un veredicto final.
    """
    from core.ia_gemini import (GeminiCliente, IAError, planificar_pruebas,
                                 veredicto_final)
    from core.registry import modulos_registrados

    estado = _estado_finalizado(pet.audit_id)
    config: Configuracion = estado["config"]
    contexto = estado.get("contexto", {})
    meta = estado["meta"]
    logger = crear_logger("ia_orquestacion")

    disponibles = sorted(modulos_registrados().keys())
    try:
        cliente = GeminiCliente(api_key=pet.api_key, modelo=pet.modelo, logger=logger)
        propuesta = planificar_pruebas(cliente, contexto, disponibles,
                                       estado["hallazgos"], meta)
    except IAError as exc:
        logger.error("IA (orquestar) fallo: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))

    # --- Lista blanca: solo se aceptan modulos existentes (la IA no inventa). ---
    plan = propuesta.get("plan", []) if isinstance(propuesta, dict) else []
    seleccionados, descartados = [], []
    for item in plan:
        nombre = (item or {}).get("modulo", "")
        if nombre in disponibles and nombre not in seleccionados:
            seleccionados.append(nombre)
        elif nombre:
            descartados.append(nombre)

    nuevos_hallazgos = []
    if seleccionados:
        # Se ejecuta un orquestador acotado a los modulos aprobados, reutilizando
        # la URL, la autorizacion y las opciones de la auditoria original.
        cfg2 = Configuracion(
            url=config.url, nombre=config.nombre, autorizado=config.autorizado,
            modulos={n: True for n in seleccionados},
            timeouts=config.timeouts, opciones=config.opciones,
        )
        orq2 = Orquestador(cfg2, logger)
        if contexto:
            orq2.contexto.update(contexto)   # reutiliza rutas/formularios/sesion
        try:
            nuevos_hallazgos = orq2.ejecutar()
        except AutorizacionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    # Consolidar hallazgos previos + nuevos y recalcular el riesgo.
    total = list(estado["hallazgos"]) + list(nuevos_hallazgos)
    resumen_total = MotorRiesgo().procesar(total)
    try:
        veredicto = veredicto_final(cliente, total, resumen_total, meta)
    except IAError as exc:
        veredicto = {"veredicto": f"(No se pudo obtener veredicto: {exc})"}

    return {
        "propuesta": propuesta,
        "modulos_ejecutados": seleccionados,
        "modulos_descartados": descartados,
        "hallazgos_nuevos": [_hallazgo_dict(h) for h in _ordenar(nuevos_hallazgos)],
        "resumen_total": resumen_total.to_dict(),
        "veredicto": veredicto,
    }


# ----------------------------------------------- Pentest activo guiado por IA
_ataques: dict[str, dict] = {}


def _worker_ataque(attack_id: str, pet: "PeticionIA"):
    estado = _ataques[attack_id]
    cola: queue.Queue = estado["cola"]
    logger = crear_logger("ia_pentest")
    try:
        from core.ia_gemini import GeminiCliente
        from core.ia_pentest import ataque_guiado

        aud = _auditorias.get(pet.audit_id)
        if aud is None or aud.get("estado") != "finalizado":
            cola.put({"tipo": "abortado", "error": "Ejecute primero una auditoria (con el crawler) en la pestaña Auditoria."})
            return
        cliente = GeminiCliente(api_key=pet.api_key, modelo=pet.modelo, logger=logger)
        resultado = ataque_guiado(cliente, aud["config"], aud.get("contexto", {}),
                                  aud["meta"], emitir=cola.put)

        # Consolidar los exitos como hallazgos y recalcular el riesgo.
        total = list(aud["hallazgos"]) + list(resultado["hallazgos_nuevos"])
        resumen_total = MotorRiesgo().procesar(total)
        # Generar el PDF del pentest para descarga.
        try:
            from reportes.generador_ia import generar_pdf_pentest
            estado["pdf"] = generar_pdf_pentest(resultado["reporte"],
                                                resultado["hallazgos_nuevos"], aud["meta"], logger)
        except Exception as exc:
            logger.error("No se pudo generar el PDF del pentest: %s", exc)
            estado["pdf"] = None
        cola.put({
            "tipo": "completado",
            "reporte": resultado["reporte"],
            "hallazgos_nuevos": [_hallazgo_dict(h) for h in _ordenar(resultado["hallazgos_nuevos"])],
            "resumen_total": resumen_total.to_dict(),
            "pdf": bool(estado.get("pdf")),
        })
    except Exception as exc:
        logger.error("Pentest IA fallo: %s", exc)
        cola.put({"tipo": "abortado", "error": str(exc)})


@app.post("/api/ia/atacar/iniciar")
def api_ia_atacar_iniciar(pet: PeticionIA):
    _estado_finalizado(pet.audit_id)  # valida que exista la auditoria
    attack_id = uuid.uuid4().hex[:12]
    _ataques[attack_id] = {"cola": queue.Queue()}
    threading.Thread(target=_worker_ataque, args=(attack_id, pet), daemon=True).start()
    return {"attack_id": attack_id}


@app.get("/api/ia/atacar/{attack_id}/eventos")
def api_ia_atacar_eventos(attack_id: str):
    estado = _ataques.get(attack_id)
    if estado is None:
        raise HTTPException(status_code=404, detail="Ataque no encontrado.")

    def generar():
        cola: queue.Queue = estado["cola"]
        while True:
            try:
                evento = cola.get(timeout=30)
            except queue.Empty:
                yield ": keep-alive\n\n"
                continue
            yield f"data: {json.dumps(evento, ensure_ascii=False)}\n\n"
            if evento.get("tipo") in ("completado", "abortado"):
                break

    return StreamingResponse(generar(), media_type="text/event-stream")


@app.get("/api/ia/atacar/{attack_id}/pdf")
def api_ia_atacar_pdf(attack_id: str):
    estado = _ataques.get(attack_id) or {}
    ruta = estado.get("pdf")
    if not ruta or not Path(ruta).exists():
        raise HTTPException(status_code=404, detail="No hay PDF de pentest disponible.")
    return FileResponse(str(ruta), media_type="application/pdf", filename=Path(ruta).name)


# Archivos estaticos (si se agregan css/js separados en el futuro).
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _puerto_libre(host: str, puerto: int) -> bool:
    """Comprueba si un puerto esta libre para escuchar."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, puerto))
            return True
        except OSError:
            return False


def main():
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Interfaz web de la herramienta de auditoria.")
    parser.add_argument("--host", default="127.0.0.1", help="Host donde escuchar (por defecto 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8000, help="Puerto inicial (por defecto 8000).")
    args = parser.parse_args()

    # Si el puerto esta ocupado, buscar el siguiente libre (hasta 10 intentos).
    puerto = args.port
    for _ in range(10):
        if _puerto_libre(args.host, puerto):
            break
        print(f"Puerto {puerto} ocupado, probando {puerto + 1}...")
        puerto += 1
    else:
        print(
            f"No se encontro un puerto libre entre {args.port} y {args.port + 9}. "
            "Cierre la aplicacion que los ocupa o indique otro con --port."
        )
        return

    print(f"Servidor en http://{args.host}:{puerto}  (Ctrl+C para detener)")
    uvicorn.run(app, host=args.host, port=puerto, log_level="warning")


if __name__ == "__main__":
    main()
