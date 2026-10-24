"""
Integracion con un modelo de IA en la nube (Google Gemini) para un analisis de
auditoria mas completo.

Filosofia de seguridad (MUY IMPORTANTE):
    La IA NUNCA ejecuta acciones por si misma. Solo:
        1) Analiza los hallazgos ya producidos por los modulos y redacta un
           informe experto (resumen, correlaciones, rutas de ataque, plan).
        2) PROPONE que modulos de deteccion (no destructivos) convendria lanzar.
    Es el codigo de la herramienta (web/app.py + el Orquestador) quien decide si
    ejecuta esa propuesta, y SOLO permite modulos ya existentes y no destructivos,
    respetando el gate de autorizacion (RF-02) y el uso responsable (RNF-03).
    La salida del modelo se trata como datos NO confiables: se filtra contra una
    lista blanca antes de actuar.

La API key NUNCA se guarda en disco ni se escribe en los logs. Se lee de la
variable de entorno GEMINI_API_KEY o se recibe en memoria desde la interfaz.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import requests

# Endpoint REST de Gemini (no requiere SDK adicional, solo requests).
_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
_MODELO_POR_DEFECTO = "gemini-3.8-flash"

# Ruta al config.yaml del proyecto (raiz = carpeta padre de core/).
_CONFIG_YAML = Path(__file__).resolve().parent.parent / "config.yaml"


def _leer_config_ia() -> dict:
    """
    Lee la seccion 'ia:' de config.yaml, si existe. Permite configurar la API key
    y el modelo desde el backend sin variables de entorno. Devuelve {} si no hay
    archivo, no hay seccion, o falla la lectura (nunca lanza).
    """
    try:
        import yaml
        with open(_CONFIG_YAML, "r", encoding="utf-8") as fh:
            datos = yaml.safe_load(fh) or {}
        seccion = datos.get("ia") or {}
        return seccion if isinstance(seccion, dict) else {}
    except Exception:
        return {}


def _resolver_api_key(explicita: str | None) -> str:
    """Prioridad: valor explicito -> variable de entorno -> config.yaml (ia.api_key)."""
    if explicita:
        return explicita
    return os.environ.get("GEMINI_API_KEY", "") or _leer_config_ia().get("api_key", "") or ""


def _resolver_modelo(explicito: str | None) -> str:
    """Prioridad: valor explicito -> variable de entorno -> config.yaml -> por defecto."""
    return (explicito or os.environ.get("GEMINI_MODEL", "")
            or _leer_config_ia().get("modelo", "") or _MODELO_POR_DEFECTO)


class IAError(RuntimeError):
    """Error al comunicarse con el modelo de IA o al interpretar su respuesta."""


class GeminiCliente:
    """Cliente minimo del API de Google Gemini, orientado a salida JSON."""

    def __init__(self, api_key: str | None = None, modelo: str | None = None,
                 logger: logging.Logger | None = None):
        self.api_key = _resolver_api_key(api_key)
        self.modelo = _resolver_modelo(modelo)
        self.logger = logger or logging.getLogger("ia_gemini")
        if not self.api_key:
            raise IAError(
                "No hay API key de Gemini configurada en el backend. Defina la "
                "variable de entorno GEMINI_API_KEY, o añada la seccion 'ia: "
                "{api_key: \"...\"}' en config.yaml."
            )

    def generar_json(self, instruccion: str, contenido: str,
                     temperatura: float = 0.2, timeout: int = 120) -> Any:
        """
        Envia una instruccion + contenido y devuelve la respuesta ya parseada
        como JSON (dict o list). Fuerza responseMimeType=application/json.
        """
        url = f"{_BASE_URL}/{self.modelo}:generateContent?key={self.api_key}"
        cuerpo = {
            "system_instruction": {"parts": [{"text": instruccion}]},
            "contents": [{"role": "user", "parts": [{"text": contenido}]}],
            "generationConfig": {
                "temperature": temperatura,
                "responseMimeType": "application/json",
                # Presupuesto amplio de salida: los modelos "thinking" (2.5+)
                # consumen tokens razonando; sin esto pueden terminar en
                # MAX_TOKENS sin devolver texto.
                "maxOutputTokens": 8192,
            },
            # Se relajan los filtros: el contenido es seguridad ofensiva sobre un
            # sistema PROPIO y autorizado. Sin esto, Gemini bloquea los prompts de
            # pentest (blockReason OTHER / SAFETY) y no devuelve candidatos.
            "safetySettings": [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ],
        }
        # No registrar nunca la URL con la key ni el cuerpo completo.
        self.logger.info("IA: consultando modelo %s...", self.modelo)
        try:
            resp = requests.post(url, json=cuerpo, timeout=timeout)
        except requests.RequestException as exc:
            self.logger.error("IA: fallo de red al contactar Gemini: %s", exc)
            raise IAError(f"No se pudo contactar al modelo de IA: {exc}") from exc

        if resp.status_code != 200:
            detalle = ""
            try:
                detalle = resp.json().get("error", {}).get("message", "")
            except Exception:
                detalle = resp.text[:200]
            self.logger.error("IA: Gemini respondio HTTP %s: %s", resp.status_code, detalle)
            raise IAError(f"El modelo respondio HTTP {resp.status_code}: {detalle}")

        try:
            datos = resp.json()
        except ValueError as exc:
            self.logger.error("IA: respuesta no era JSON: %s", exc)
            raise IAError(f"Respuesta no valida del modelo: {exc}") from exc

        # ¿Bloqueado por filtros de seguridad, sin candidatos?
        candidatos = datos.get("candidates") or []
        if not candidatos:
            motivo = (datos.get("promptFeedback", {}) or {}).get("blockReason", "sin candidatos")
            self.logger.error("IA: Gemini no devolvio candidatos (%s).", motivo)
            raise IAError(f"El modelo no devolvio contenido (motivo: {motivo}).")

        cand = candidatos[0]
        partes = (cand.get("content", {}) or {}).get("parts") or []
        texto = "".join(p.get("text", "") for p in partes).strip()
        if not texto:
            finish = cand.get("finishReason", "desconocido")
            self.logger.error("IA: candidato sin texto (finishReason=%s).", finish)
            raise IAError(
                f"El modelo termino sin texto (finishReason={finish}). "
                f"Si es MAX_TOKENS, el modelo consumio el presupuesto razonando; "
                f"pruebe con otro modelo (p. ej. 'gemini-3.8-flash') o reduzca la entrada."
            )

        self.logger.info("IA: respuesta recibida (%d caracteres).", len(texto))
        try:
            return json.loads(texto)
        except ValueError as exc:
            self.logger.error("IA: el texto no era JSON valido: %s", texto[:300])
            raise IAError(f"El modelo no devolvio JSON valido: {exc}") from exc


# --------------------------------------------------------------------------- #
#  Funciones de alto nivel: analisis y planificacion sobre los hallazgos.      #
# --------------------------------------------------------------------------- #

_INSTRUCCION_ANALISTA = (
    "Eres un auditor de seguridad senior (OWASP, ISO 27005, NIST SP 800-30). "
    "Recibes los hallazgos de un escaneo automatizado de una cooperativa financiera "
    "y su matriz de riesgo. Analiza con rigor y en español, para un equipo de "
    "desarrollo NO especializado en seguridad. NO inventes vulnerabilidades que no "
    "esten respaldadas por los hallazgos. Responde SOLO con el JSON pedido."
)


def _resumir_hallazgos(hallazgos: list, resumen, meta: dict) -> str:
    """Serializa hallazgos y resumen a un texto compacto para el prompt."""
    lista = []
    for h in hallazgos:
        lista.append({
            "titulo": h.titulo or h.categoria.value,
            "severidad": h.severidad.value,
            "categoria": h.categoria.value,
            "cvss": h.cvss,
            "nivel_riesgo": h.nivel_riesgo,
            "ubicacion": h.ubicacion,
            "evidencia": h.evidencia,
            "modulo": h.modulo_origen,
        })
    payload = {
        "objetivo": meta.get("url", ""),
        "nombre": meta.get("nombre_objetivo", ""),
        "resumen_riesgo": resumen.to_dict() if hasattr(resumen, "to_dict") else {},
        "hallazgos": lista,
    }
    return json.dumps(payload, ensure_ascii=False)


def analizar_hallazgos(cliente: GeminiCliente, hallazgos: list, resumen, meta: dict) -> dict:
    """Pide a la IA un analisis experto de los hallazgos ya detectados."""
    instruccion = _INSTRUCCION_ANALISTA + (
        " Devuelve un objeto JSON con las claves: "
        "'resumen_ejecutivo' (string, 3-5 frases), "
        "'correlaciones' (array de strings: relaciones entre hallazgos), "
        "'rutas_ataque' (array de objetos {escenario, pasos[], hallazgos_implicados[], gravedad}), "
        "'plan_remediacion' (array de objetos {prioridad, accion, esfuerzo}), "
        "'conclusion' (string)."
    )
    contenido = "Hallazgos y matriz de riesgo del escaneo:\n" + _resumir_hallazgos(hallazgos, resumen, meta)
    return cliente.generar_json(instruccion, contenido)


def planificar_pruebas(cliente: GeminiCliente, contexto: dict, modulos_disponibles: list[str],
                       hallazgos: list, meta: dict) -> dict:
    """
    Pide a la IA que PROPONGA que modulos NO destructivos ejecutar a continuacion,
    a partir de lo ya descubierto (rutas, formularios, tecnologias). La propuesta
    se valida despues contra la lista blanca en el codigo; la IA no ejecuta nada.
    """
    instruccion = _INSTRUCCION_ANALISTA + (
        " Ahora debes PROPONER pruebas adicionales NO destructivas para una auditoria "
        "responsable (sin fuerza bruta real, sin post-explotacion, sin payloads "
        "destructivos). SOLO puedes elegir modulos de la lista 'modulos_disponibles'. "
        "Devuelve un objeto JSON con: 'plan' (array de objetos "
        "{modulo, motivo, prioridad}) y 'observaciones' (string). "
        "No incluyas modulos que no esten en la lista."
    )
    payload = {
        "modulos_disponibles": modulos_disponibles,
        "contexto_descubierto": {
            "urls_con_parametros": contexto.get("urls_con_parametros", []),
            "formularios": contexto.get("formularios", []),
            "rutas_descubiertas": contexto.get("rutas_descubiertas", []),
        },
        "hallazgos_actuales": [
            {"titulo": h.titulo or h.categoria.value, "modulo": h.modulo_origen,
             "severidad": h.severidad.value}
            for h in hallazgos
        ],
        "objetivo": meta.get("url", ""),
    }
    contenido = json.dumps(payload, ensure_ascii=False)
    return cliente.generar_json(instruccion, contenido)


def veredicto_final(cliente: GeminiCliente, hallazgos: list, resumen, meta: dict) -> dict:
    """Tras ejecutar las pruebas propuestas, pide a la IA un veredicto global."""
    instruccion = _INSTRUCCION_ANALISTA + (
        " Estos son TODOS los hallazgos tras ejecutar las pruebas adicionales. "
        "Devuelve un objeto JSON con: 'veredicto' (string), "
        "'riesgo_global' ('Critico'|'Alto'|'Medio'|'Bajo'), "
        "'hallazgos_clave' (array de strings), "
        "'siguientes_pasos' (array de strings)."
    )
    contenido = "Hallazgos finales:\n" + _resumir_hallazgos(hallazgos, resumen, meta)
    return cliente.generar_json(instruccion, contenido)
