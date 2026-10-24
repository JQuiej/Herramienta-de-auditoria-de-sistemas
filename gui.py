"""
Interfaz grafica de la herramienta de auditoria de seguridad.

Interfaz de escritorio sencilla (Tkinter, sin dependencias externas) que permite
configurar el objetivo, seleccionar los modulos y ejecutar la auditoria mostrando
en tiempo real el progreso de cada modulo, el resumen de riesgo y el detalle de
los hallazgos.

El escaneo corre en un hilo aparte para no bloquear la ventana; la comunicacion
con la interfaz se hace mediante una cola de eventos que la interfaz consulta
periodicamente (patron seguro para Tkinter).

Uso:
    python gui.py
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import ttk, messagebox

# Importar el paquete de modulos registra todos los modulos disponibles.
import modules  # noqa: F401
from core.config_loader import Configuracion, validar_url, ConfigError
from core.logger import crear_logger
from core.orchestrator import Orquestador, AutorizacionError
from core.registry import modulos_registrados
from reportes.generador import GeneradorReportes
from riesgo.motor_riesgo import MotorRiesgo


# Colores por severidad para la tabla de hallazgos (sobrios, sin saturar).
COLOR_SEVERIDAD = {
    "Critica": "#c0392b",
    "Alta": "#e67e22",
    "Media": "#c9a600",
    "Baja": "#2e7d32",
    "Informativa": "#5a6b7b",
}

ESTADO_INICIAL = "Pendiente"


class AplicacionAuditoria(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Herramienta de Auditoria de Seguridad")
        self.geometry("980x720")
        self.minsize(880, 620)
        self.configure(bg="#f4f6f8")

        self.cola: queue.Queue = queue.Queue()
        self.vars_modulos: dict[str, tk.BooleanVar] = {}
        self.estado_modulos: dict[str, ttk.Label] = {}
        self.hallazgos: list = []
        self.rutas_informe: dict = {}
        self.en_ejecucion = False

        self._configurar_estilos()
        self._construir_interfaz()
        self.after(100, self._procesar_cola)

    # ------------------------------------------------------------- estilos
    def _configurar_estilos(self):
        estilo = ttk.Style(self)
        try:
            estilo.theme_use("clam")
        except tk.TclError:
            pass
        estilo.configure("TFrame", background="#f4f6f8")
        estilo.configure("TLabel", background="#f4f6f8", foreground="#2c3e50", font=("Segoe UI", 10))
        estilo.configure("Titulo.TLabel", font=("Segoe UI", 15, "bold"), foreground="#1f3a5f")
        estilo.configure("Seccion.TLabel", font=("Segoe UI", 11, "bold"), foreground="#1f3a5f")
        estilo.configure("Estado.TLabel", font=("Segoe UI", 9))
        estilo.configure("TButton", font=("Segoe UI", 10))
        estilo.configure("Accion.TButton", font=("Segoe UI", 10, "bold"))
        estilo.configure("TCheckbutton", background="#f4f6f8", font=("Segoe UI", 10))
        estilo.configure("Treeview", font=("Segoe UI", 9), rowheight=24)
        estilo.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    # ---------------------------------------------------------- construccion
    def _construir_interfaz(self):
        cont = ttk.Frame(self, padding=16)
        cont.pack(fill="both", expand=True)

        ttk.Label(cont, text="Herramienta de Auditoria de Seguridad", style="Titulo.TLabel").pack(anchor="w")
        ttk.Label(cont, text="Cooperativa Nuevo Amanecer, R.L.  -  Escaneo automatizado OWASP Top 10").pack(anchor="w", pady=(0, 12))

        # Zona superior: configuracion (izq) y modulos (der).
        superior = ttk.Frame(cont)
        superior.pack(fill="x")
        self._construir_config(superior)
        self._construir_modulos(superior)

        # Controles y barra de progreso.
        self._construir_controles(cont)

        # Zona de resultados.
        self._construir_resultados(cont)

    def _construir_config(self, padre):
        marco = ttk.LabelFrame(padre, text=" Configuracion del objetivo ", padding=12)
        marco.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ttk.Label(marco, text="URL del objetivo (SAG o portal):").grid(row=0, column=0, sticky="w", pady=3)
        self.entry_url = ttk.Entry(marco, width=38)
        self.entry_url.insert(0, "https://")
        self.entry_url.grid(row=1, column=0, sticky="we", pady=(0, 8))

        ttk.Label(marco, text="Nombre descriptivo:").grid(row=2, column=0, sticky="w", pady=3)
        self.entry_nombre = ttk.Entry(marco, width=38)
        self.entry_nombre.insert(0, "Auditoria SAG")
        self.entry_nombre.grid(row=3, column=0, sticky="we", pady=(0, 8))

        self.var_autorizado = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(
            marco,
            text="Cuento con autorizacion explicita para auditar este objetivo",
            variable=self.var_autorizado,
        )
        chk.grid(row=4, column=0, sticky="w", pady=(4, 2))
        ttk.Label(
            marco,
            text="La auditoria no iniciara sin esta confirmacion (RF-02).",
            foreground="#7f8c8d", font=("Segoe UI", 8),
        ).grid(row=5, column=0, sticky="w")

        marco.columnconfigure(0, weight=1)

    def _construir_modulos(self, padre):
        marco = ttk.LabelFrame(padre, text=" Modulos de deteccion ", padding=12)
        marco.pack(side="left", fill="both", expand=True, padx=(8, 0))

        barra = ttk.Frame(marco)
        barra.pack(fill="x", pady=(0, 6))
        ttk.Button(barra, text="Seleccionar todos", command=lambda: self._marcar_todos(True)).pack(side="left")
        ttk.Button(barra, text="Ninguno", command=lambda: self._marcar_todos(False)).pack(side="left", padx=6)

        # Lista con scroll por si hay muchos modulos.
        contenedor = ttk.Frame(marco)
        contenedor.pack(fill="both", expand=True)
        canvas = tk.Canvas(contenedor, height=170, bg="#ffffff", highlightthickness=1,
                           highlightbackground="#dfe4ea")
        scroll = ttk.Scrollbar(contenedor, orient="vertical", command=canvas.yview)
        interno = ttk.Frame(canvas)
        interno.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=interno, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        interno.configure(style="Blanco.TFrame")
        ttk.Style(self).configure("Blanco.TFrame", background="#ffffff")

        for i, nombre in enumerate(sorted(modulos_registrados())):
            fila = tk.Frame(interno, bg="#ffffff")
            fila.pack(fill="x", padx=6, pady=1)
            var = tk.BooleanVar(value=True)
            self.vars_modulos[nombre] = var
            chk = tk.Checkbutton(fila, text=nombre, variable=var, bg="#ffffff",
                                 anchor="w", font=("Segoe UI", 9), activebackground="#ffffff")
            chk.pack(side="left")
            estado = ttk.Label(fila, text=ESTADO_INICIAL, style="Estado.TLabel",
                               background="#ffffff", foreground="#7f8c8d")
            estado.pack(side="right")
            self.estado_modulos[nombre] = estado

    def _construir_controles(self, padre):
        marco = ttk.Frame(padre)
        marco.pack(fill="x", pady=12)

        self.btn_iniciar = ttk.Button(marco, text="Iniciar auditoria", style="Accion.TButton",
                                      command=self._iniciar_auditoria)
        self.btn_iniciar.pack(side="left")

        self.btn_pdf = ttk.Button(marco, text="Abrir informe PDF", command=self._abrir_pdf,
                                   state="disabled")
        self.btn_pdf.pack(side="left", padx=8)

        self.btn_excel = ttk.Button(marco, text="Abrir Excel", command=self._abrir_excel,
                                    state="disabled")
        self.btn_excel.pack(side="left")

        self.lbl_estado = ttk.Label(marco, text="Listo.", foreground="#34495e")
        self.lbl_estado.pack(side="left", padx=12)

        self.progreso = ttk.Progressbar(marco, mode="determinate", length=240)
        self.progreso.pack(side="right")

    def _construir_resultados(self, padre):
        marco = ttk.LabelFrame(padre, text=" Resultados ", padding=10)
        marco.pack(fill="both", expand=True)

        self.lbl_resumen = ttk.Label(marco, text="Aun no se ha ejecutado ninguna auditoria.",
                                     style="Seccion.TLabel")
        self.lbl_resumen.pack(anchor="w", pady=(0, 8))

        cuerpo = ttk.Frame(marco)
        cuerpo.pack(fill="both", expand=True)

        columnas = ("severidad", "titulo", "categoria", "modulo")
        self.tabla = ttk.Treeview(cuerpo, columns=columnas, show="headings", height=10)
        self.tabla.heading("severidad", text="Severidad")
        self.tabla.heading("titulo", text="Hallazgo")
        self.tabla.heading("categoria", text="Categoria OWASP")
        self.tabla.heading("modulo", text="Modulo")
        self.tabla.column("severidad", width=90, anchor="w")
        self.tabla.column("titulo", width=340, anchor="w")
        self.tabla.column("categoria", width=210, anchor="w")
        self.tabla.column("modulo", width=130, anchor="w")

        scroll_v = ttk.Scrollbar(cuerpo, orient="vertical", command=self.tabla.yview)
        self.tabla.configure(yscrollcommand=scroll_v.set)
        self.tabla.pack(side="left", fill="both", expand=True)
        scroll_v.pack(side="right", fill="y")

        for sev, color in COLOR_SEVERIDAD.items():
            self.tabla.tag_configure(sev, foreground=color)

        self.tabla.bind("<<TreeviewSelect>>", self._mostrar_detalle)

        # Panel de detalle del hallazgo seleccionado.
        self.txt_detalle = tk.Text(marco, height=6, wrap="word", font=("Segoe UI", 9),
                                   bg="#ffffff", relief="solid", borderwidth=1, state="disabled")
        self.txt_detalle.pack(fill="x", pady=(8, 0))

    # ---------------------------------------------------------- acciones UI
    def _marcar_todos(self, valor: bool):
        for var in self.vars_modulos.values():
            var.set(valor)

    def _iniciar_auditoria(self):
        if self.en_ejecucion:
            return

        # Validaciones previas (flujos A1 y A2 del caso de uso "Configurar auditoria").
        try:
            url = validar_url(self.entry_url.get())
        except ConfigError as exc:
            messagebox.showerror("URL invalida", str(exc))
            return

        if not self.var_autorizado.get():
            messagebox.showwarning(
                "Autorizacion requerida",
                "Debe confirmar que cuenta con autorizacion explicita para auditar el "
                "objetivo antes de iniciar (RF-02).",
            )
            return

        modulos = {n: v.get() for n, v in self.vars_modulos.items()}
        if not any(modulos.values()):
            messagebox.showwarning("Sin modulos", "Seleccione al menos un modulo de deteccion.")
            return

        # Reiniciar estado visual.
        self._limpiar_resultados()
        for nombre, activo in modulos.items():
            self._set_estado_modulo(nombre, ESTADO_INICIAL if activo else "Desactivado", "#7f8c8d")

        config = Configuracion(
            url=url,
            nombre=self.entry_nombre.get() or "Auditoria",
            autorizado=True,
            modulos=modulos,
            timeouts={"por_modulo_seg": 120},
            opciones={"crawler": {"max_paginas": 25}, "autenticacion": {"max_intentos": 4}},
        )

        self.en_ejecucion = True
        self.btn_iniciar.configure(state="disabled")
        self.btn_pdf.configure(state="disabled")
        self.btn_excel.configure(state="disabled")
        self.lbl_estado.configure(text="Ejecutando auditoria...")
        self.progreso.configure(value=0)

        hilo = threading.Thread(target=self._worker, args=(config,), daemon=True)
        hilo.start()

    def _worker(self, config: Configuracion):
        """Se ejecuta en un hilo aparte: corre la auditoria y publica eventos."""
        logger = crear_logger(config.nombre.replace(" ", "_"))
        try:
            orq = Orquestador(config, logger, listener=self.cola.put)
            hallazgos = orq.ejecutar()

            resumen = MotorRiesgo().procesar(hallazgos)
            meta = {"url": config.url, "nombre_objetivo": config.nombre}
            rutas = GeneradorReportes(logger=logger).generar(hallazgos, resumen, meta)

            self.cola.put({
                "tipo": "completado",
                "hallazgos": hallazgos,
                "resumen": resumen,
                "rutas": rutas,
            })
        except AutorizacionError as exc:
            self.cola.put({"tipo": "abortado", "error": str(exc)})
        except Exception as exc:  # cualquier fallo inesperado del hilo
            self.cola.put({"tipo": "abortado", "error": f"Error inesperado: {exc}"})

    # ---------------------------------------------------------- cola/eventos
    def _procesar_cola(self):
        """Consulta la cola de eventos y actualiza la interfaz (hilo principal)."""
        try:
            while True:
                evento = self.cola.get_nowait()
                self._manejar_evento(evento)
        except queue.Empty:
            pass
        self.after(100, self._procesar_cola)

    def _manejar_evento(self, ev: dict):
        tipo = ev.get("tipo")
        if tipo == "inicio":
            self._total_modulos = len(ev["modulos"])
            self._completados = 0
            self.progreso.configure(maximum=self._total_modulos, value=0)
            self.lbl_estado.configure(text=f"Ejecutando {self._total_modulos} modulo(s)...")
        elif tipo == "modulo_inicio":
            self._set_estado_modulo(ev["nombre"], "Ejecutando...", "#1f6fb2")
        elif tipo == "modulo_fin":
            n = ev["hallazgos"]
            texto = f"Completado ({n})" if n else "Completado"
            self._set_estado_modulo(ev["nombre"], texto, "#2e7d32")
            self._avanzar_progreso()
        elif tipo == "modulo_error":
            self._set_estado_modulo(ev["nombre"], "Error (omitido)", "#c0392b")
            self._avanzar_progreso()
        elif tipo == "fin":
            self.lbl_estado.configure(text="Consolidando y generando informe...")
        elif tipo == "completado":
            self._finalizar(ev)
        elif tipo == "abortado":
            self.en_ejecucion = False
            self.btn_iniciar.configure(state="normal")
            self.lbl_estado.configure(text="Auditoria abortada.")
            messagebox.showerror("Auditoria abortada", ev.get("error", "Error desconocido."))

    def _avanzar_progreso(self):
        self._completados = getattr(self, "_completados", 0) + 1
        self.progreso.configure(value=self._completados)

    def _finalizar(self, ev: dict):
        self.en_ejecucion = False
        self.hallazgos = ev["hallazgos"]
        self.rutas_informe = ev["rutas"]
        resumen = ev["resumen"]

        # Rellenar la tabla, mas graves primero.
        orden = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Informativa": 4}
        for h in sorted(self.hallazgos, key=lambda x: orden.get(x.severidad.value, 9)):
            self.tabla.insert("", "end",
                              values=(h.severidad.value, h.titulo or h.categoria.value,
                                      h.categoria.value, h.modulo_origen),
                              tags=(h.severidad.value,))

        criticos = resumen.por_nivel.get("Critico", 0)
        altos = resumen.por_nivel.get("Alto", 0)
        self.lbl_resumen.configure(
            text=(f"Total: {resumen.total} hallazgo(s)   |   "
                  f"Criticos: {criticos}   Altos: {altos}   "
                  f"Medios: {resumen.por_nivel.get('Medio', 0)}   "
                  f"Bajos: {resumen.por_nivel.get('Bajo', 0)}   |   "
                  f"Riesgo promedio: {resumen.riesgo_promedio:.1f} / 25")
        )
        self.lbl_estado.configure(text="Auditoria finalizada.")
        self.progreso.configure(value=self.progreso["maximum"])
        self.btn_iniciar.configure(state="normal")
        if self.rutas_informe.get("pdf"):
            self.btn_pdf.configure(state="normal")
        if self.rutas_informe.get("excel"):
            self.btn_excel.configure(state="normal")

    # ---------------------------------------------------------- utilidades
    def _set_estado_modulo(self, nombre: str, texto: str, color: str):
        lbl = self.estado_modulos.get(nombre)
        if lbl is not None:
            lbl.configure(text=texto, foreground=color)

    def _limpiar_resultados(self):
        for fila in self.tabla.get_children():
            self.tabla.delete(fila)
        self._set_detalle("")
        self.lbl_resumen.configure(text="Ejecutando auditoria...")

    def _mostrar_detalle(self, _evento):
        sel = self.tabla.selection()
        if not sel:
            return
        idx = self.tabla.index(sel[0])
        orden = {"Critica": 0, "Alta": 1, "Media": 2, "Baja": 3, "Informativa": 4}
        ordenados = sorted(self.hallazgos, key=lambda x: orden.get(x.severidad.value, 9))
        if idx >= len(ordenados):
            return
        h = ordenados[idx]
        detalle = (
            f"{h.titulo or h.categoria.value}\n"
            f"Severidad: {h.severidad.value}   |   CVSS: {h.cvss}   |   "
            f"Riesgo: {h.nivel_riesgo} (P{h.probabilidad} x I{h.impacto})\n"
            f"Ubicacion: {h.ubicacion or 'N/D'}\n\n"
            f"Evidencia: {h.evidencia}\n\n"
            f"Recomendacion: {h.recomendacion}"
        )
        self._set_detalle(detalle)

    def _set_detalle(self, texto: str):
        self.txt_detalle.configure(state="normal")
        self.txt_detalle.delete("1.0", "end")
        self.txt_detalle.insert("1.0", texto)
        self.txt_detalle.configure(state="disabled")

    def _abrir_archivo(self, clave: str, etiqueta: str):
        """Abre el informe generado (PDF o Excel) con la aplicacion del sistema."""
        ruta = self.rutas_informe.get(clave)
        if ruta and Path(ruta).exists():
            import os
            try:
                os.startfile(str(Path(ruta).resolve()))  # Windows
            except AttributeError:
                webbrowser.open(Path(ruta).resolve().as_uri())  # otros SO
        else:
            messagebox.showinfo("Informe", f"No hay informe {etiqueta} disponible.")

    def _abrir_pdf(self):
        self._abrir_archivo("pdf", "PDF")

    def _abrir_excel(self):
        self._abrir_archivo("excel", "Excel")


def main():
    app = AplicacionAuditoria()
    app.mainloop()


if __name__ == "__main__":
    main()
