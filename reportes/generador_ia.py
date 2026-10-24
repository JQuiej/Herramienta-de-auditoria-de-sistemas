"""
Generacion de informes PDF para la pestaña de IA:
  - Analisis de seguridad con IA (analizar_hallazgos).
  - Informe de pentest activo guiado por IA (ataque_guiado).

Usa fpdf2 (Python puro, sin dependencias del sistema), con el mismo estilo visual
que el informe de auditoria. Cada multi_cell vuelve al margen izquierdo
(new_x=LMARGIN) para evitar el desbordamiento a la derecha.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

_AZUL = (37, 99, 235)
_AZUL_CLARO = (190, 210, 245)
_GRIS = (90, 90, 90)
_RGB_SEVERIDAD = {
    "Critica": (198, 40, 40), "Alta": (230, 126, 34), "Media": (241, 196, 15),
    "Baja": (39, 174, 96), "Informativa": (120, 120, 120),
}

_DIR_SALIDA = Path(__file__).resolve().parent.parent / "reportes_generados"


def _lat(s) -> str:
    """Texto seguro para las fuentes core de fpdf (latin-1)."""
    return str(s if s is not None else "").encode("latin-1", "replace").decode("latin-1")


def _nuevo_pdf(titulo: str, meta: dict):
    from fpdf import FPDF
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    ancho = pdf.w - pdf.l_margin - pdf.r_margin
    # Cabecera.
    pdf.set_fill_color(*_AZUL)
    pdf.rect(0, 0, pdf.w, 32, style="F")
    pdf.set_xy(pdf.l_margin, 8)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 17)
    pdf.cell(ancho, 9, _lat(titulo), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(ancho, 6, _lat("Cooperativa Nuevo Amanecer, R.L.  -  Analisis asistido por IA (Gemini)"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_text_color(60, 60, 60)
    pdf.set_font("Helvetica", "", 10)
    obj = f"{meta.get('nombre_objetivo', '')} ({meta.get('url', '')})"
    pdf.cell(ancho, 6, _lat(f"Objetivo: {obj}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(ancho, 6, _lat(f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M')}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    return pdf, ancho


def _titulo(pdf, ancho, texto):
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*_AZUL)
    pdf.cell(ancho, 8, _lat(texto), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*_AZUL_CLARO)
    y = pdf.get_y()
    pdf.line(pdf.l_margin, y, pdf.l_margin + ancho, y)
    pdf.ln(2)


def _parrafo(pdf, ancho, texto, size=10, color=(40, 40, 40)):
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(ancho, 5.5, _lat(texto), new_x="LMARGIN", new_y="NEXT")


def _vinetas(pdf, ancho, items):
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    if not items:
        _parrafo(pdf, ancho, "—", color=_GRIS)
        return
    for it in items:
        pdf.multi_cell(ancho, 5.5, _lat("- " + str(it)), new_x="LMARGIN", new_y="NEXT")


def _guardar(pdf, base_nombre: str, logger) -> Path | None:
    _DIR_SALIDA.mkdir(exist_ok=True)
    marca = datetime.now().strftime("%Y%m%d_%H%M%S")
    ruta = _DIR_SALIDA / f"{base_nombre}_{marca}.pdf"
    try:
        pdf.output(str(ruta))
        if logger:
            logger.info("Informe IA PDF generado: %s", ruta)
        return ruta
    except Exception as exc:
        if logger:
            logger.error("No se pudo generar el PDF de IA: %s", exc)
        return None


# --------------------------------------------------------------- Analisis IA
def generar_pdf_analisis(analisis: dict, meta: dict, logger: logging.Logger | None = None) -> Path | None:
    try:
        pdf, ancho = _nuevo_pdf("Analisis de Seguridad con IA", meta)
    except Exception as exc:
        if logger:
            logger.warning("No se pudo iniciar el PDF (falta fpdf2?): %s", exc)
        return None

    a = analisis or {}
    _titulo(pdf, ancho, "1. Resumen ejecutivo")
    _parrafo(pdf, ancho, a.get("resumen_ejecutivo", "—"))

    _titulo(pdf, ancho, "2. Correlacion de hallazgos")
    _vinetas(pdf, ancho, a.get("correlaciones", []))

    _titulo(pdf, ancho, "3. Rutas de ataque probables")
    rutas = a.get("rutas_ataque", []) or []
    if not rutas:
        _parrafo(pdf, ancho, "—", color=_GRIS)
    for r in rutas:
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(*_RGB_SEVERIDAD.get(str(r.get("gravedad", "")).capitalize(), (60, 60, 60)))
        pdf.multi_cell(ancho, 6, _lat(f"[{r.get('gravedad', '')}] {r.get('escenario', '')}"),
                       new_x="LMARGIN", new_y="NEXT")
        _vinetas(pdf, ancho, r.get("pasos", []))
        impl = r.get("hallazgos_implicados", [])
        if impl:
            _parrafo(pdf, ancho, "Hallazgos implicados: " + ", ".join(map(str, impl)), size=9, color=_GRIS)
        pdf.ln(2)

    _titulo(pdf, ancho, "4. Plan de remediacion priorizado")
    plan = a.get("plan_remediacion", []) or []
    if not plan:
        _parrafo(pdf, ancho, "—", color=_GRIS)
    for p in plan:
        pdf.multi_cell(ancho, 5.5, _lat(f"[{p.get('prioridad', '')}] {p.get('accion', '')}  "
                                        f"(esfuerzo: {p.get('esfuerzo', '-')})"),
                       new_x="LMARGIN", new_y="NEXT")

    _titulo(pdf, ancho, "5. Conclusion")
    _parrafo(pdf, ancho, a.get("conclusion", "—"))

    nombre = "informe_IA_analisis_" + str(meta.get("nombre_objetivo", "objetivo")).replace(" ", "_")
    return _guardar(pdf, nombre, logger)


# --------------------------------------------------------------- Pentest IA
def generar_pdf_pentest(reporte: dict, hallazgos: list, meta: dict,
                        logger: logging.Logger | None = None) -> Path | None:
    try:
        pdf, ancho = _nuevo_pdf("Informe de Pentest con IA", meta)
    except Exception as exc:
        if logger:
            logger.warning("No se pudo iniciar el PDF (falta fpdf2?): %s", exc)
        return None

    r = reporte or {}
    _titulo(pdf, ancho, "1. Veredicto")
    pdf.set_font("Helvetica", "B", 10.5)
    pdf.set_text_color(*_RGB_SEVERIDAD.get(str(r.get("riesgo_global", "")).capitalize(), (60, 60, 60)))
    pdf.multi_cell(ancho, 6, _lat("Riesgo global: " + str(r.get("riesgo_global", "-"))),
                   new_x="LMARGIN", new_y="NEXT")
    _parrafo(pdf, ancho, r.get("resumen", "—"))

    _titulo(pdf, ancho, "2. Lo que la IA logro vulnerar")
    _vinetas(pdf, ancho, r.get("logrado", []))

    _titulo(pdf, ancho, "3. Lo que resistio")
    _vinetas(pdf, ancho, r.get("no_logrado", []))

    _titulo(pdf, ancho, f"4. Vulnerabilidades confirmadas ({len(hallazgos or [])})")
    if not hallazgos:
        _parrafo(pdf, ancho, "La IA no logro vulnerar el objetivo (buen resultado de seguridad).", color=_GRIS)
    for h in (hallazgos or []):
        sev = h.severidad.value if hasattr(h, "severidad") else h.get("severidad", "")
        titulo = h.titulo if hasattr(h, "titulo") else h.get("titulo", "")
        ubic = h.ubicacion if hasattr(h, "ubicacion") else h.get("ubicacion", "")
        evid = h.evidencia if hasattr(h, "evidencia") else h.get("evidencia", "")
        reco = h.recomendacion if hasattr(h, "recomendacion") else h.get("recomendacion", "")
        rgb = _RGB_SEVERIDAD.get(sev, (120, 120, 120))
        pdf.set_fill_color(*rgb)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.multi_cell(ancho, 7, _lat(f"[{sev}] {titulo}"), border=0, fill=True,
                       new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(90, 90, 90)
        pdf.set_font("Helvetica", "", 9)
        if ubic:
            pdf.multi_cell(ancho, 5, _lat(f"Ubicacion: {ubic}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(40, 40, 40)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(ancho, 5, _lat("Evidencia:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(ancho, 5, _lat(evid), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(ancho, 5, _lat("Recomendacion:"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(ancho, 5, _lat(reco), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    _titulo(pdf, ancho, "5. Recomendaciones")
    _vinetas(pdf, ancho, r.get("recomendaciones", []))

    nombre = "informe_IA_pentest_" + str(meta.get("nombre_objetivo", "objetivo")).replace(" ", "_")
    return _guardar(pdf, nombre, logger)
