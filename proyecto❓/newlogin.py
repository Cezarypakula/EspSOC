import customtkinter
from tkinter import filedialog, messagebox
from collections import Counter
import webbrowser
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from socket import gethostbyname, gaierror
import pandas as pd
import plotly.express as px
import plotly.io as pio
import tempfile
import os

API_KEY = "66d00a63db6ec9baebea11609c9d6d9b94e78cadd185a326397375c0e661bd81"

# ================== FUNCIONES DE ANÁLISIS ==================
def verificar_dominio(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            # Verificar también en Spamhaus
            spamhaus_result = check_spamhaus(dominio)
            
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                return f"[⚠️] {dominio} - Malicioso: {stats['malicious']}, Sospechoso: {stats['suspicious']} | {spamhaus_result}\n", "malicious"
            else:
                return f"[✅] {dominio} es seguro | {spamhaus_result}\n", "safe"
        else:
            return f"[❌] No se pudo analizar {dominio} (Código {response.status_code})\n", "error"
    except requests.exceptions.RequestException as e:
        return f"[❌] Error con {dominio}: {e}\n", "error"

def check_spamhaus(domain_or_ip):
    try:
        if not domain_or_ip.replace('.', '').isdigit():
            try:
                ip = gethostbyname(domain_or_ip)
            except gaierror:
                return "🔍 No se pudo resolver IP"
        else:
            ip = domain_or_ip
        
        reversed_ip = '.'.join(ip.split('.')[::-1])
        query = f"{reversed_ip}.zen.spamhaus.org"
        
        try:
            gethostbyname(query)
            return "⛔ En lista negra (Spamhaus)"
        except gaierror:
            return "✅ No en listas negras"
    except Exception as e:
        return f"❌ Error Spamhaus: {str(e)}"

def leer_dominios(archivo):
    try:
        with open(archivo, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        return []

# ================== INTERFAZ DE VALIDACIÓN ==================
def abrir_app_validacion(admin_window=None):
    if admin_window:
        admin_window.withdraw()
    
    ventana_validacion = customtkinter.CTk()
    ventana_validacion.title("Validación de Dominios/IP")
    ventana_validacion.geometry("1000x700")
    
    # Frame para controles laterales
    frame_controles = customtkinter.CTkFrame(ventana_validacion, width=220)
    frame_controles.pack(side="left", fill="y", padx=10, pady=10)
    
    # Frame principal
    frame_principal = customtkinter.CTkFrame(ventana_validacion)
    frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)
    
    # Información de análisis
    info_frame = customtkinter.CTkFrame(frame_controles)
    info_frame.pack(pady=10, fill="x")
    
    info_label = customtkinter.CTkLabel(info_frame, text="Información de análisis", font=("Arial", 14))
    info_label.pack(pady=5)
    
    global info_stats_label
    info_stats_label = customtkinter.CTkLabel(
        info_frame, 
        text="Dominios: 0\nSeguros: 0\nMaliciosos: 0\nErrores: 0",
        font=("Arial", 12),
        wraplength=180
    )
    info_stats_label.pack(pady=5)
    
    # Botones de control
    control_frame = customtkinter.CTkFrame(frame_controles)
    control_frame.pack(pady=10, fill="x")
    
    btn_importar = customtkinter.CTkButton(
        control_frame,
        text="Importar archivo",
        command=lambda: importar_archivo_validacion(resultados_textbox, info_stats_label, frame_graficos),
        width=200
    )
    btn_importar.pack(pady=5)
    
    btn_guardar = customtkinter.CTkButton(
        control_frame,
        text="Guardar resultados",
        command=lambda: guardar_resultados_validacion(resultados_textbox),
        width=200
    )
    btn_guardar.pack(pady=5)
    
    btn_grafico = customtkinter.CTkButton(
        control_frame,
        text="Mostrar gráfico",
        command=lambda: mostrar_grafico_interactivo(resultados_textbox),
        width=200,
        fg_color="#6a0dad",
        hover_color="#4b0082"
    )
    btn_grafico.pack(pady=5)
    
    btn_firewall = customtkinter.CTkButton(
        control_frame,
        text="Agregar al firewall",
        command=lambda: agregar_al_firewall(resultados_textbox),
        width=200
    )
    btn_firewall.pack(pady=5)
    
    # Área de resultados
    resultados_frame = customtkinter.CTkFrame(frame_principal)
    resultados_frame.pack(expand=True, fill="both", padx=10, pady=10)
    
    resultados_textbox = customtkinter.CTkTextbox(
        resultados_frame,
        wrap="word",
        font=("Consolas", 12)
    )
    resultados_textbox.pack(expand=True, fill="both")
    
    # Frame para gráficos
    frame_graficos = customtkinter.CTkFrame(frame_principal, height=200)
    frame_graficos.pack(fill="x", padx=10, pady=5)
    
    # Configurar tags para colores
    resultados_textbox.tag_config("safe", foreground="green")
    resultados_textbox.tag_config("malicious", foreground="red")
    resultados_textbox.tag_config("error", foreground="orange")
    resultados_textbox.tag_config("info", foreground="blue")
    resultados_textbox.tag_config("spamhaus", foreground="purple")
    
    # Botón de regreso
    btn_volver = customtkinter.CTkButton(
        frame_controles,
        text="Volver",
        command=lambda: cerrar_validacion(ventana_validacion, admin_window),
        width=200
    )
    btn_volver.pack(pady=20)
    
    # Mostrar instrucciones
    resultados_textbox.insert("end", "Instrucciones:\n", "info")
    resultados_textbox.insert("end", "1. Importe un archivo TXT con dominios/IPs\n")
    resultados_textbox.insert("end", "2. Los resultados mostrarán análisis de VirusTotal y Spamhaus\n")
    resultados_textbox.insert("end", "3. Use los botones para guardar o visualizar gráficos\n\n", "info")
    
    ventana_validacion.protocol("WM_DELETE_WINDOW", lambda: cerrar_validacion(ventana_validacion, admin_window))
    ventana_validacion.mainloop()

# ================== FUNCIONES DE INTERFAZ ==================
def importar_archivo_validacion(text_widget, stats_label, graph_frame):
    archivo = filedialog.askopenfilename(
        title="Seleccionar archivo", 
        filetypes=[("Archivos de texto", "*.txt")]
    )
    
    if archivo:
        text_widget.delete("1.0", "end")
        text_widget.insert("end", f"[🔍] Analizando archivo: {archivo}\n\n", "info")
        
        dominios = leer_dominios(archivo)
        if not dominios:
            text_widget.insert("end", "[❌] No hay dominios válidos para analizar\n", "error")
            return
        
        # Mostrar resumen inicial
        total = len(dominios)
        unicos = len(set(dominios))
        repetidos = total - unicos
        
        text_widget.insert("end", f"Resumen del archivo:\n", "info")
        text_widget.insert("end", f"- Total de entradas: {total}\n")
        text_widget.insert("end", f"- Entradas únicas: {unicos}\n")
        text_widget.insert("end", f"- Entradas repetidas: {repetidos}\n\n", "info")
        
        # Analizar dominios
        analizar_dominios(archivo, text_widget, stats_label, graph_frame)

def analizar_dominios(archivo, text_widget, stats_label, graph_frame):
    dominios = leer_dominios(archivo)
    if not dominios:
        text_widget.insert("end", "[❌] No hay dominios para analizar.\n", "error")
        return

    seguros = 0
    maliciosos = 0
    errores = 0

    with ThreadPoolExecutor(max_workers=4) as executor:
        for resultado, tipo in executor.map(verificar_dominio, dominios):
            if tipo == "safe":
                seguros += 1
                tag = "safe"
            elif tipo == "malicious":
                maliciosos += 1
                tag = "malicious"
            else:
                errores += 1
                tag = "error"
            
            text_widget.insert("end", resultado, tag)
            text_widget.see("end")
            text_widget.update()

    # Actualizar estadísticas
    stats_label.configure(text=f"Dominios: {len(dominios)}\nSeguros: {seguros}\nMaliciosos: {maliciosos}\nErrores: {errores}")
    
    # Mostrar gráfico
    mostrar_grafico_basico(seguros, maliciosos, errores, graph_frame)

def mostrar_grafico_basico(seguros, maliciosos, errores, frame):
    # Limpiar frame anterior
    for widget in frame.winfo_children():
        widget.destroy()
    
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(["Seguros", "Maliciosos", "Errores"], [seguros, maliciosos, errores], 
           color=["green", "red", "orange"])
    ax.set_title("Resumen de Análisis")
    
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

def mostrar_grafico_interactivo(text_widget):
    contenido = text_widget.get("1.0", "end")
    seguros = contenido.count("[✅]")
    maliciosos = contenido.count("[⚠️]")
    errores = contenido.count("[❌]") - contenido.count("Error Spamhaus")
    
    data = {
        "Categoría": ["Seguros", "Maliciosos", "Errores"],
        "Cantidad": [seguros, maliciosos, errores]
    }
    
    fig = px.pie(data, names="Categoría", values="Cantidad", 
                 title="Distribución de Dominios",
                 color="Categoría",
                 color_discrete_map={"Seguros":"green", "Maliciosos":"red", "Errores":"orange"})
    
    # Guardar temporalmente y abrir en navegador
    temp_file = os.path.join(tempfile.gettempdir(), "grafico_dominios.html")
    fig.write_html(temp_file)
    webbrowser.open(f"file://{temp_file}")

def guardar_resultados_validacion(text_widget):
    resultados = text_widget.get("1.0", "end").strip()
    if not resultados:
        messagebox.showwarning("Advertencia", "No hay resultados para guardar")
        return
    
    archivo = filedialog.asksaveasfilename(
        title="Guardar resultados",
        defaultextension=".txt",
        filetypes=[("Archivos de texto", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
    )
    
    if archivo:
        try:
            if archivo.endswith(".csv"):
                import csv
                lineas = [line.strip() for line in resultados.split("\n") if line.strip()]
                with open(archivo, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Dominio", "Estado"])
                    for linea in lineas:
                        if linea.startswith(("[✅]", "[⚠️]", "[❌]")):
                            estado = "Seguro" if "[✅]" in linea else "Malicioso" if "[⚠️]" in linea else "Error"
                            dominio = linea.split("] ")[1].split(" - ")[0]
                            writer.writerow([dominio, estado])
            elif archivo.endswith(".json"):
                import json
                lineas = [line.strip() for line in resultados.split("\n") if line.strip()]
                data = []
                for linea in lineas:
                    if linea.startswith(("[✅]", "[⚠️]", "[❌]")):
                        estado = "Seguro" if "[✅]" in linea else "Malicioso" if "[⚠️]" in linea else "Error"
                        dominio = linea.split("] ")[1].split(" - ")[0]
                        data.append({"dominio": dominio, "estado": estado})
                with open(archivo, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(archivo, "w") as f:
                    f.write(resultados)
            
            text_widget.insert("end", f"\n[✅] Resultados guardados en {archivo}\n", "info")
        except Exception as e:
            text_widget.insert("end", f"\n[❌] Error al guardar: {str(e)}\n", "error")

def agregar_al_firewall(text_widget):
    contenido = text_widget.get("1.0", "end")
    lineas_maliciosas = [line for line in contenido.split("\n") if "[⚠️]" in line]
    
    if lineas_maliciosas:
        dominios_maliciosos = [line.split(" - ")[0].replace("[⚠️] ", "") for line in lineas_maliciosas]
        text_widget.insert("end", "\nDominios para bloquear:\n", "info")
        for dominio in dominios_maliciosos:
            text_widget.insert("end", f"- {dominio}\n")
    else:
        text_widget.insert("end", "\nNo se encontraron dominios maliciosos para bloquear\n", "info")

# ================== INTERFAZ PRINCIPAL ==================
def abrir_interfaz_admin(login_window):
    login_window.destroy()

    ventana_admin = customtkinter.CTk()
    ventana_admin.title("Interfaz de Administrador")
    ventana_admin.geometry("900x650")

    frame_botones = customtkinter.CTkFrame(ventana_admin, width=220)
    frame_botones.pack(side="left", fill="y", padx=10, pady=10)

    frame_principal = customtkinter.CTkFrame(ventana_admin)
    frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)

    # Descripción/ayuda
    frame_descripcion = customtkinter.CTkFrame(frame_principal)
    frame_descripcion.pack(fill="x", padx=5, pady=5)

    descripcion_label = customtkinter.CTkLabel(
        frame_descripcion, 
        text="Seleccione una opción del menú",
        font=("Arial", 12),
        wraplength=500
    )
    descripcion_label.pack(pady=10)

    # Contenido dinámico
    frame_contenido = customtkinter.CTkFrame(frame_principal)
    frame_contenido.pack(expand=True, fill="both", padx=5, pady=5)

    def mostrar_descripcion(texto):
        descripcion_label.configure(text=texto)

    def limpiar_descripcion(event=None):
        descripcion_label.configure(text="Seleccione una opción del menú")

    def limpiar_contenido():
        for widget in frame_contenido.winfo_children():
            widget.destroy()

    def mostrar_importar_txt():
        limpiar_contenido()
        
        frame_acciones = customtkinter.CTkFrame(frame_contenido)
        frame_acciones.pack(fill="x", padx=5, pady=5)
        
        boton_examinar = customtkinter.CTkButton(
            frame_acciones,
            text="Examinar archivo TXT",
            command=lambda: cargar_archivo_txt(),
            width=200
        )
        boton_examinar.pack(side="left", padx=5)
        
        boton_limpiar = customtkinter.CTkButton(
            frame_acciones,
            text="Limpiar",
            command=lambda: limpiar_resultados(),
            width=200
        )
        boton_limpiar.pack(side="left", padx=5)
        
        boton_guardar_procesado = customtkinter.CTkButton(
            frame_acciones,
            text="Guardar limpio",
            command=lambda: guardar_archivo_procesado(),
            fg_color="#2aa44f",
            hover_color="#1d7a3b",
            width=200
        )
        boton_guardar_procesado.pack(side="left", padx=5)
        
        global frame_resultados
        frame_resultados = customtkinter.CTkFrame(frame_contenido)
        frame_resultados.pack(expand=True, fill="both", padx=5, pady=5)
        
        tabview = customtkinter.CTkTabview(frame_resultados)
        tabview.pack(expand=True, fill="both")
        
        global tabs, dominios_actuales
        dominios_actuales = []
        tabs = {
            "contenido": tabview.add("Contenido"),
            "repetidos": tabview.add("Repetidos"),
            "estadisticas": tabview.add("Estadísticas")
        }
        
        for tab in tabs.values():
            scroll = customtkinter.CTkScrollableFrame(tab)
            scroll.pack(expand=True, fill="both")
            
            label = customtkinter.CTkLabel(scroll, text="No hay datos para mostrar", wraplength=500)
            label.pack(pady=10)
            
            setattr(tab, "content_label", label)

    def cargar_archivo_txt():
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo TXT",
            filetypes=[("Archivos de texto", "*.txt")]
        )
        
        if archivo:
            try:
                with open(archivo, 'r') as f:
                    lineas = [line.strip() for line in f.readlines() if line.strip()]
                
                if not lineas:
                    messagebox.showwarning("Advertencia", "El archivo está vacío")
                    return
                
                global dominios_actuales
                dominios_actuales = lineas
                
                total = len(lineas)
                contador = Counter(lineas)
                repetidos = {k: v for k, v in contador.items() if v > 1}
                unicos = len(contador)
                
                contenido_texto = "\n".join(lineas)
                tabs["contenido"].content_label.configure(
                    text=f"Total de entradas: {total}\n\nContenido:\n{contenido_texto}",
                    justify="left"
                )
                
                if repetidos:
                    repetidos_texto = "\n".join([f"{k} (repetido {v} veces)" for k, v in repetidos.items()])
                    tabs["repetidos"].content_label.configure(
                        text=f"Entradas repetidas ({len(repetidos)}):\n\n{repetidos_texto}",
                        justify="left"
                    )
                else:
                    tabs["repetidos"].content_label.configure(
                        text="No se encontraron entradas repetidas",
                        justify="left"
                    )
                
                stats_text = (
                    f"Total de entradas: {total}\n"
                    f"Entradas únicas: {unicos}\n"
                    f"Entradas repetidas: {len(repetidos)}\n"
                    f"Porcentaje de duplicados: {len(repetidos)/unicos*100:.2f}%"
                )
                tabs["estadisticas"].content_label.configure(
                    text=stats_text,
                    justify="left"
                )
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {str(e)}")

    def limpiar_resultados():
        for tab in tabs.values():
            tab.content_label.configure(text="No hay datos para mostrar")
        global dominios_actuales
        dominios_actuales = []

    def guardar_archivo_procesado():
        if not dominios_actuales:
            messagebox.showwarning("Advertencia", "No hay datos para guardar")
            return
        
        dominios_procesados = set()
        
        for dominio in dominios_actuales:
            dominio_limpio = dominio.lower().strip()
            
            if dominio_limpio.startswith(('http://', 'https://')):
                dominio_limpio = dominio_limpio.split('://')[1]
            
            if dominio_limpio.startswith('www.'):
                dominio_limpio = dominio_limpio[4:]
            
            dominio_limpio = dominio_limpio.split('/')[0].split('?')[0].split(':')[0]
            
            if dominio_limpio and '.' in dominio_limpio:
                dominios_procesados.add(dominio_limpio)
        
        if not dominios_procesados:
            messagebox.showwarning("Advertencia", "No se encontraron dominios válidos para guardar")
            return
        
        archivo = filedialog.asksaveasfilename(
            title="Guardar dominios procesados",
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
        )
        
        if archivo:
            try:
                if archivo.endswith(".csv"):
                    import csv
                    with open(archivo, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Dominio"])
                        for dominio in sorted(dominios_procesados):
                            writer.writerow([dominio])
                elif archivo.endswith(".json"):
                    import json
                    with open(archivo, 'w') as f:
                        json.dump(sorted(list(dominios_procesados)), f, indent=2)
                else:
                    with open(archivo, 'w') as f:
                        f.write('\n'.join(sorted(dominios_procesados)))
                
                messagebox.showinfo("Éxito", f"Dominios guardados en {archivo}")
                
                tabs["estadisticas"].content_label.configure(
                    text=f"Dominios únicos guardados: {len(dominios_procesados)}\n\n" +
                         "Ejemplos:\n" + '\n'.join(sorted(dominios_procesados)[:5]) + 
                         ("\n..." if len(dominios_procesados) > 5 else ""),
                    justify="left"
                )
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")

    # Botones principales
    botones = [
        ("Importar txt", "Importar y analizar archivos TXT con dominios/IPs", mostrar_importar_txt),
        ("Verificar db", "Verificar la integridad de la base de datos", lambda: limpiar_contenido()),
        ("Validar txt", "Validar dominios/ips con VirusTotal y Spamhaus", lambda: abrir_app_validacion(ventana_admin))
    ]

    for texto_boton, descripcion, comando in botones:
        boton = customtkinter.CTkButton(
            frame_botones, 
            text=texto_boton,
            command=comando,
            width=200
        )
        boton.pack(pady=5, padx=10, fill="x")
        
        boton.bind("<Enter>", lambda event, desc=descripcion: mostrar_descripcion(desc))
        boton.bind("<Leave>", limpiar_descripcion)

    ventana_admin.mainloop()

# ================== FUNCIONES AUXILIARES ==================
def cerrar_validacion(validacion_window, admin_window):
    validacion_window.destroy()
    if admin_window:
        admin_window.deiconify()

# ================== INTERFAZ DE LOGIN ==================
def login():
    nombre = entrada_usuario.get()
    contraseña = entrada_contraseña.get()
    rol = "administrador"

    if rol == "administrador":
        etiqueta_resultado.configure(text=f"Bienvenido, {nombre}. Rol: Administrador", text_color="green")
        abrir_interfaz_admin(app)  
    elif rol:
        etiqueta_resultado.configure(text=f"Bienvenido, {nombre}. Rol: {rol}", text_color="blue")
    else:
        etiqueta_resultado.configure(text="Credenciales incorrectas.", text_color="red")

# ================== CONFIGURACIÓN INICIAL ==================
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("400x300")
app.title("Sistema de Login")

etiqueta_usuario = customtkinter.CTkLabel(app, text="Usuario:")
etiqueta_usuario.pack(pady=10)
entrada_usuario = customtkinter.CTkEntry(app)
entrada_usuario.pack(pady=10)

etiqueta_contraseña = customtkinter.CTkLabel(app, text="Contraseña:")
etiqueta_contraseña.pack(pady=10)
entrada_contraseña = customtkinter.CTkEntry(app, show="*")
entrada_contraseña.pack(pady=10)

boton_login = customtkinter.CTkButton(app, text="Login", command=login)
boton_login.pack(pady=10)

etiqueta_resultado = customtkinter.CTkLabel(app, text="")
etiqueta_resultado.pack(pady=10)

app.mainloop()

import customtkinter
from tkinter import filedialog, messagebox
from collections import Counter
import webbrowser
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from socket import gethostbyname, gaierror
import pandas as pd
import plotly.express as px
import tempfile
import os
import sys
import sqlite3
from hashlib import sha256
from validar import AppValidacion
from pyqt import *

# ================== INTERFAZ ROOT (SUPERUSUARIO) ==================
class AppRoot(customtkinter.CTk):
    def __init__(self, login_window, username):
        super().__init__()
        self.login_window = login_window
        self.username = username
        
        self.title(f"Interfaz Root - {username}")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Configuración inicial de la base de datos
        self.inicializar_base_reportes()
        self.setup_ui()
        self.mainloop()
    
    def inicializar_base_reportes(self):
        """Crea la base de datos para almacenar reportes si no existe"""
        conexion = sqlite3.connect('reportes.db')
        cursor = conexion.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reportes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usuario TEXT NOT NULL,
            tipo TEXT NOT NULL,
            contenido TEXT NOT NULL,
            resultado TEXT NOT NULL
        )
        ''')
        
        conexion.commit()
        conexion.close()
    
    def setup_ui(self):
        # Frame principal con dos columnas
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Frame de navegación (izquierda)
        self.frame_navegacion = customtkinter.CTkFrame(self, width=200, corner_radius=0)
        self.frame_navegacion.grid(row=0, column=0, sticky="nsew")
        self.frame_navegacion.grid_rowconfigure(6, weight=1)
        
        # Frame de contenido (derecha)
        self.frame_contenido = customtkinter.CTkFrame(self, corner_radius=0)
        self.frame_contenido.grid(row=0, column=1, sticky="nsew")
        self.frame_contenido.grid_rowconfigure(0, weight=1)
        self.frame_contenido.grid_columnconfigure(0, weight=1)
        
        # Barra superior con información de usuario
        self.frame_superior = customtkinter.CTkFrame(self.frame_contenido, height=50)
        self.frame_superior.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        self.label_usuario = customtkinter.CTkLabel(
            self.frame_superior, 
            text=f"Usuario ROOT: {self.username}",
            font=("Arial", 14, "bold")
        )
        self.label_usuario.pack(side="left", padx=20)
        
        boton_cerrar_sesion = customtkinter.CTkButton(
            self.frame_superior,
            text="Cerrar sesión",
            command=self.cerrar_sesion,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cerrar_sesion.pack(side="right", padx=20)
        
        # Botones de navegación
        botones_nav = [
            ("📊 Dashboard", self.mostrar_dashboard),
            ("📈 Gráficos", self.mostrar_graficos),
            ("📋 Reportes", self.mostrar_reportes),
            ("👥 Usuarios", self.mostrar_usuarios),
            ("⚙️ Configuración", self.mostrar_configuracion)
        ]
        
        for i, (texto, comando) in enumerate(botones_nav):
            boton = customtkinter.CTkButton(
                self.frame_navegacion,
                text=texto,
                command=comando,
                height=40,
                anchor="w",
                font=("Arial", 14),
                corner_radius=0
            )
            boton.grid(row=i, column=0, sticky="ew", padx=5, pady=5)
        
        self.mostrar_dashboard()
    
    def limpiar_contenido(self):
        """Limpia el frame de contenido"""
        for widget in self.frame_contenido.winfo_children():
            if widget != self.frame_superior:
                widget.destroy()
    
    def mostrar_dashboard(self):
        """Muestra el panel principal con resumen de actividad"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(0, weight=1)
        
        stats = self.obtener_estadisticas()
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Dashboard Root - Resumen del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.grid(row=0, column=0, pady=20, sticky="n")
        
        frame_metricas = customtkinter.CTkFrame(frame_principal)
        frame_metricas.grid(row=1, column=0, pady=10, sticky="nsew")
        
        metricas = [
            ("📊 Reportes totales", stats['total_reportes']),
            ("👥 Usuarios registrados", stats['total_usuarios']),
            ("⚠️ Alertas recientes", stats['alertas_7dias']),
            ("🔄 Última actividad", stats['ultima_actividad'])
        ]
        
        for i, (titulo, valor) in enumerate(metricas):
            frame_metrica = customtkinter.CTkFrame(frame_metricas)
            frame_metrica.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            
            label_titulo = customtkinter.CTkLabel(
                frame_metrica,
                text=titulo,
                font=("Arial", 12)
            )
            label_titulo.pack(pady=(10, 0))
            
            label_valor = customtkinter.CTkLabel(
                frame_metrica,
                text=str(valor),
                font=("Arial", 24, "bold")
            )
            label_valor.pack(pady=(0, 10))
    
    def mostrar_graficos(self):
        """Muestra gráficos de actividad reciente"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Visualización de Gráficos",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener datos para gráficos
        datos = self.obtener_datos_graficos()
        
        # Gráfico 1: Actividad por usuario
        fig1, ax1 = plt.subplots(figsize=(8, 4))
        datos['actividad_usuarios'].plot(kind='bar', ax=ax1, color='skyblue')
        ax1.set_title('Actividad por Usuario (últimos 30 días)')
        ax1.set_ylabel('Número de acciones')
        
        canvas1 = FigureCanvasTkAgg(fig1, master=frame_principal)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
        
        # Gráfico 2: Tipos de reportes
        fig2, ax2 = plt.subplots(figsize=(8, 4))
        datos['tipos_reportes'].plot(kind='pie', autopct='%1.1f%%', ax=ax2)
        ax2.set_title('Distribución de Tipos de Reportes')
        ax2.set_ylabel('')
        
        canvas2 = FigureCanvasTkAgg(fig2, master=frame_principal)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
    
    def mostrar_reportes(self):
        """Muestra el historial de reportes generados"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Historial de Reportes",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener reportes de la base de datos
        reportes = self.obtener_ultimos_reportes()
        
        # Crear tabla de reportes
        frame_tabla = customtkinter.CTkScrollableFrame(frame_principal)
        frame_tabla.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Encabezados de la tabla
        encabezados = ["ID", "Fecha", "Usuario", "Tipo", "Acciones"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                frame_tabla,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados)-1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")
        
        # Filas con datos
        for i, reporte in enumerate(reportes, start=1):
            for j, campo in enumerate(reporte[:4]):  # Mostrar solo los primeros 4 campos
                label = customtkinter.CTkLabel(
                    frame_tabla,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")
            
            # Botón para ver detalles
            boton_ver = customtkinter.CTkButton(
                frame_tabla,
                text="Ver Detalles",
                command=lambda r=reporte: self.mostrar_detalle_reporte(r),
                width=100
            )
            boton_ver.grid(row=i, column=4, padx=5, pady=5)
    
    def mostrar_usuarios(self):
        """Muestra la gestión de usuarios del sistema"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Gestión de Usuarios",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener lista de usuarios
        usuarios = self.obtener_usuarios()
        
        # Crear tabla de usuarios
        frame_tabla = customtkinter.CTkScrollableFrame(frame_principal, height=300)
        frame_tabla.pack(fill="x", padx=20, pady=10)
        
        # Encabezados de la tabla
        encabezados = ["ID", "Nombre", "Rol", "Acciones"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                frame_tabla,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados)-1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")
        
        # Filas con datos
        for i, usuario in enumerate(usuarios, start=1):
            for j, campo in enumerate(usuario[:3]):  # Mostrar id, nombre y rol
                label = customtkinter.CTkLabel(
                    frame_tabla,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")
            
            # Botones de acción
            frame_botones = customtkinter.CTkFrame(frame_tabla, fg_color="transparent")
            frame_botones.grid(row=i, column=3, padx=5, pady=5, sticky="e")
            
            boton_editar = customtkinter.CTkButton(
                frame_botones,
                text="Editar",
                command=lambda u=usuario: self.editar_usuario(u),
                width=80
            )
            boton_editar.pack(side="left", padx=2)
            
            boton_eliminar = customtkinter.CTkButton(
                frame_botones,
                text="Eliminar",
                command=lambda u=usuario: self.eliminar_usuario(u),
                width=80,
                fg_color="#d9534f",
                hover_color="#c9302c"
            )
            boton_eliminar.pack(side="left", padx=2)
        
        # Botón para agregar nuevo usuario
        boton_nuevo = customtkinter.CTkButton(
            frame_principal,
            text="+ Agregar Usuario",
            command=self.agregar_usuario,
            fg_color="#5cb85c",
            hover_color="#4cae4c",
            height=40,
            width=200
        )
        boton_nuevo.pack(pady=20)
    
    # ========== FUNCIONES DE DATOS ==========
    def obtener_estadisticas(self):
        """Obtiene estadísticas del sistema para el dashboard"""
        conn = sqlite3.connect('reportes.db')
        cursor = conn.cursor()
        
        # Obtener total de reportes
        cursor.execute("SELECT COUNT(*) FROM reportes")
        total_reportes = cursor.fetchone()[0]
        
        # Obtener total de usuarios
        conn_usuarios = sqlite3.connect('usuarios.db')
        cursor_usuarios = conn_usuarios.cursor()
        cursor_usuarios.execute("SELECT COUNT(*) FROM usuarios")
        total_usuarios = cursor_usuarios.fetchone()[0]
        conn_usuarios.close()
        
        # Obtener alertas recientes
        cursor.execute("""
            SELECT COUNT(*) FROM reportes 
            WHERE fecha >= datetime('now', '-7 days')
            AND resultado LIKE '%malicioso%' OR resultado LIKE '%sospechoso%'
        """)
        alertas_7dias = cursor.fetchone()[0]
        
        # Obtener última actividad
        cursor.execute("SELECT MAX(fecha) FROM reportes")
        ultima_actividad = cursor.fetchone()[0] or "Ninguna"
        
        conn.close()
        
        return {
            'total_reportes': total_reportes,
            'total_usuarios': total_usuarios,
            'alertas_7dias': alertas_7dias,
            'ultima_actividad': ultima_actividad
        }
    
    def obtener_datos_graficos(self):
        """Obtiene datos para generar gráficos"""
        conn = sqlite3.connect('reportes.db')
        
        # Actividad por usuario
        df_actividad = pd.read_sql("""
            SELECT usuario, COUNT(*) as acciones 
            FROM reportes 
            WHERE fecha >= datetime('now', '-30 days')
            GROUP BY usuario
            ORDER BY acciones DESC
            LIMIT 10
        """, conn)
        
        # Tipos de reportes
        df_tipos = pd.read_sql("""
            SELECT tipo, COUNT(*) as cantidad
            FROM reportes
            GROUP BY tipo
        """, conn)
        
        conn.close()
        
        return {
            'actividad_usuarios': df_actividad.set_index('usuario')['acciones'],
            'tipos_reportes': df_tipos.set_index('tipo')['cantidad']
        }
    
    def obtener_ultimos_reportes(self, limite=20):
        """Obtiene los últimos reportes generados"""
        conn = sqlite3.connect('reportes.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, fecha, tipo, contenido, resultado
            FROM reportes
            ORDER BY fecha DESC
            LIMIT ?
        ''', (limite,))
        
        reportes = cursor.fetchall()
        conn.close()
        return reportes
    
    def obtener_usuarios(self):
        """Obtiene la lista de usuarios del sistema"""
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, nombre, rol FROM usuarios ORDER BY nombre")
        usuarios = cursor.fetchall()
        conn.close()
        return usuarios
    
    # ========== FUNCIONES DE INTERACCIÓN ==========
    def mostrar_detalle_reporte(self, reporte):
        """Muestra los detalles completos de un reporte"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title(f"Detalle Reporte #{reporte[0]}")
        ventana.geometry("800x600")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Mostrar información básica
        info_basica = f"""
        ID: {reporte[0]}
        Fecha: {reporte[1]}
        Usuario: {reporte[2]}
        Tipo: {reporte[3]}
        """
        
        label_info = customtkinter.CTkLabel(
            frame_principal,
            text=info_basica,
            font=("Arial", 14),
            justify="left"
        )
        label_info.pack(pady=10, padx=20, anchor="w")
        
        # Mostrar contenido con scroll
        label_contenido = customtkinter.CTkLabel(
            frame_principal,
            text="Contenido:",
            font=("Arial", 12, "bold")
        )
        label_contenido.pack(pady=(10, 0), padx=20, anchor="w")
        
        texto_contenido = customtkinter.CTkTextbox(
            frame_principal,
            wrap="word",
            height=150
        )
        texto_contenido.insert("1.0", reporte[4])
        texto_contenido.configure(state="disabled")
        texto_contenido.pack(fill="x", padx=20, pady=(0, 10))
        
        # Mostrar resultado con scroll
        label_resultado = customtkinter.CTkLabel(
            frame_principal,
            text="Resultado:",
            font=("Arial", 12, "bold")
        )
        label_resultado.pack(pady=(10, 0), padx=20, anchor="w")
        
        texto_resultado = customtkinter.CTkTextbox(
            frame_principal,
            wrap="word",
            height=150
        )
        texto_resultado.insert("1.0", reporte[5])
        texto_resultado.configure(state="disabled")
        texto_resultado.pack(fill="x", padx=20, pady=(0, 10))
        
        # Botón para cerrar
        boton_cerrar = customtkinter.CTkButton(
            frame_principal,
            text="Cerrar",
            command=ventana.destroy
        )
        boton_cerrar.pack(pady=10)
    
    def editar_usuario(self, usuario):
        """Abre ventana para editar usuario"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title(f"Editar Usuario #{usuario[0]}")
        ventana.geometry("400x300")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Campos del formulario
        label_nombre = customtkinter.CTkLabel(frame_principal, text="Nombre:")
        label_nombre.pack(pady=(10, 0))
        
        entrada_nombre = customtkinter.CTkEntry(frame_principal, width=300)
        entrada_nombre.insert(0, usuario[1])
        entrada_nombre.pack(pady=5)
        
        label_rol = customtkinter.CTkLabel(frame_principal, text="Rol:")
        label_rol.pack(pady=(10, 0))
        
        opciones_rol = ["root", "administrador", "usuario"]
        combo_rol = customtkinter.CTkComboBox(
            frame_principal,
            values=opciones_rol,
            width=300
        )
        combo_rol.set(usuario[2])
        combo_rol.pack(pady=5)
        
        label_password = customtkinter.CTkLabel(frame_principal, text="Nueva contraseña (opcional):")
        label_password.pack(pady=(10, 0))
        
        entrada_password = customtkinter.CTkEntry(frame_principal, width=300, show="*")
        entrada_password.pack(pady=5)
        
        # Botones de acción
        frame_botones = customtkinter.CTkFrame(frame_principal, fg_color="transparent")
        frame_botones.pack(pady=20)
        
        boton_guardar = customtkinter.CTkButton(
            frame_botones,
            text="Guardar",
            command=lambda: self.guardar_cambios_usuario(
                usuario[0],
                entrada_nombre.get(),
                combo_rol.get(),
                entrada_password.get(),
                ventana
            ),
            width=120
        )
        boton_guardar.pack(side="left", padx=10)
        
        boton_cancelar = customtkinter.CTkButton(
            frame_botones,
            text="Cancelar",
            command=ventana.destroy,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cancelar.pack(side="right", padx=10)
    
    def guardar_cambios_usuario(self, id_usuario, nombre, rol, password, ventana):
        """Guarda los cambios del usuario en la base de datos"""
        if not nombre or not rol:
            messagebox.showerror("Error", "Nombre y rol son obligatorios")
            return
        
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        try:
            if password:  # Si se proporcionó nueva contraseña
                password_hash = sha256(password.encode()).hexdigest()
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, contraseña=?, rol=?
                    WHERE id=?
                """, (nombre, password_hash, rol, id_usuario))
            else:  # Mantener la contraseña actual
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, rol=?
                    WHERE id=?
                """, (nombre, rol, id_usuario))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario actualizado correctamente")
            ventana.destroy()
            self.mostrar_usuarios()  # Refrescar la lista
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo actualizar el usuario: {str(e)}")
        finally:
            conn.close()
    
    def eliminar_usuario(self, usuario):
        """Elimina un usuario del sistema"""
        if usuario[1] == self.username:
            messagebox.showerror("Error", "No puedes eliminarte a ti mismo")
            return
        
        confirmacion = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Estás seguro de eliminar al usuario {usuario[1]}? Esta acción no se puede deshacer."
        )
        
        if confirmacion:
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute("DELETE FROM usuarios WHERE id=?", (usuario[0],))
                conn.commit()
                messagebox.showinfo("Éxito", "Usuario eliminado correctamente")
                self.mostrar_usuarios()  # Refrescar la lista
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar el usuario: {str(e)}")
            finally:
                conn.close()
    
    def agregar_usuario(self):
        """Abre ventana para agregar nuevo usuario"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title("Agregar Nuevo Usuario")
        ventana.geometry("400x300")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Campos del formulario
        label_nombre = customtkinter.CTkLabel(frame_principal, text="Nombre de usuario:")
        label_nombre.pack(pady=(10, 0))
        
        entrada_nombre = customtkinter.CTkEntry(frame_principal, width=300)
        entrada_nombre.pack(pady=5)
        
        label_password = customtkinter.CTkLabel(frame_principal, text="Contraseña:")
        label_password.pack(pady=(10, 0))
        
        entrada_password = customtkinter.CTkEntry(frame_principal, width=300, show="*")
        entrada_password.pack(pady=5)
        
        label_rol = customtkinter.CTkLabel(frame_principal, text="Rol:")
        label_rol.pack(pady=(10, 0))
        
        opciones_rol = ["root", "administrador", "usuario"]
        combo_rol = customtkinter.CTkComboBox(
            frame_principal,
            values=opciones_rol,
            width=300
        )
        combo_rol.set("usuario")
        combo_rol.pack(pady=5)
        
        # Botones de acción
        frame_botones = customtkinter.CTkFrame(frame_principal, fg_color="transparent")
        frame_botones.pack(pady=20)
        
        boton_guardar = customtkinter.CTkButton(
            frame_botones,
            text="Guardar",
            command=lambda: self.crear_nuevo_usuario(
                entrada_nombre.get(),
                entrada_password.get(),
                combo_rol.get(),
                ventana
            ),
            width=120
        )
        boton_guardar.pack(side="left", padx=10)
        
        boton_cancelar = customtkinter.CTkButton(
            frame_botones,
            text="Cancelar",
            command=ventana.destroy,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cancelar.pack(side="right", padx=10)
    
    def crear_nuevo_usuario(self, nombre, password, rol, ventana):
        """Crea un nuevo usuario en la base de datos"""
        if not nombre or not password or not rol:
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
        
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        try:
            # Verificar si el usuario ya existe
            cursor.execute("SELECT id FROM usuarios WHERE nombre=?", (nombre,))
            if cursor.fetchone():
                messagebox.showerror("Error", "El nombre de usuario ya existe")
                return
            
            # Crear hash de la contraseña
            password_hash = sha256(password.encode()).hexdigest()
            
            # Insertar nuevo usuario
            cursor.execute("""
                INSERT INTO usuarios (nombre, contraseña, rol)
                VALUES (?, ?, ?)
            """, (nombre, password_hash, rol))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario creado correctamente")
            ventana.destroy()
            self.mostrar_usuarios()  # Refrescar la lista
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el usuario: {str(e)}")
        finally:
            conn.close()
    
    def mostrar_configuracion(self):
        """Muestra la configuración del sistema"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Configuración del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Aquí podrías añadir opciones de configuración como:
        # - Tema de la interfaz (oscuro/claro)
        # - Configuración de APIs
        # - Preferencias de notificaciones
        # - etc.
        
        label_info = customtkinter.CTkLabel(
            frame_principal,
            text="Configuración avanzada del sistema para usuarios root",
            font=("Arial", 14)
        )
        label_info.pack(pady=10)
    
    def cerrar_sesion(self):
        """Cierra la sesión y vuelve al login"""
        self.destroy()
        self.login_window.deiconify()
    
    def on_close(self):
        """Maneja el cierre de la ventana"""
        self.cerrar_sesion()

# ================== MODIFICACIÓN EN EL LOGIN PARA SOPORTAR ROOT ==================
class AppLogin(customtkinter.CTk):
    # ... (el resto del código permanece igual)
    
    def abrir_ventana_principal(self, rol, username):
        if rol == "root":
            self.destroy()
            AppRoot(None, username)  
        elif rol == "administrador":
            self.destroy()
            AppAdmin(None, username)
        else:
            messagebox.showinfo("Acceso", f"Bienvenido usuario {username} (rol: {rol})")

def inicializar_base_datos():
    conexion = sqlite3.connect('usuarios.db')
    cursor = conexion.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        contraseña TEXT NOT NULL,
        rol TEXT NOT NULL
    )
    ''')
    
    cursor.execute("SELECT * FROM usuarios WHERE nombre='admin'")
    if not cursor.fetchone():
        password_hash = sha256('admin123'.encode()).hexdigest()
        cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES (?, ?, ?)", 
                      ('admin', password_hash, 'administrador'))
    
    cursor.execute("SELECT * FROM usuarios WHERE nombre='root'")
    if not cursor.fetchone():
        password_hash = sha256('root123'.encode()).hexdigest()
        cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES (?, ?, ?)", 
                      ('root', password_hash, 'root'))
    
    conexion.commit()
    conexion.close()

    import customtkinter
from tkinter import filedialog, messagebox
from collections import Counter
import webbrowser
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from socket import gethostbyname, gaierror
import pandas as pd
import plotly.express as px
import plotly.io as pio
import tempfile
import os

API_KEY = "66d00a63db6ec9baebea11609c9d6d9b94e78cadd185a326397375c0e661bd81"

# ================== FUNCIONES DE ANÁLISIS ==================
def verificar_dominio(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            # Verificar también en Spamhaus
            spamhaus_result = check_spamhaus(dominio)
            
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                return f"[⚠️] {dominio} - Malicioso: {stats['malicious']}, Sospechoso: {stats['suspicious']} | {spamhaus_result}\n", "malicious"
            else:
                return f"[✅] {dominio} es seguro | {spamhaus_result}\n", "safe"
        else:
            return f"[❌] No se pudo analizar {dominio} (Código {response.status_code})\n", "error"
    except requests.exceptions.RequestException as e:
        return f"[❌] Error con {dominio}: {e}\n", "error"

def check_spamhaus(domain_or_ip):
    try:
        if not domain_or_ip.replace('.', '').isdigit():
            try:
                ip = gethostbyname(domain_or_ip)
            except gaierror:
                return "🔍 No se pudo resolver IP"
        else:
            ip = domain_or_ip
        
        reversed_ip = '.'.join(ip.split('.')[::-1])
        query = f"{reversed_ip}.zen.spamhaus.org"
        
        try:
            gethostbyname(query)
            return "⛔ En lista negra (Spamhaus)"
        except gaierror:
            return "✅ No en listas negras"
    except Exception as e:
        return f"❌ Error Spamhaus: {str(e)}"

def leer_dominios(archivo):
    try:
        with open(archivo, "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        return []

# ================== INTERFAZ DE VALIDACIÓN ==================
def abrir_app_validacion(admin_window=None):
    if admin_window:
        admin_window.withdraw()
    
    ventana_validacion = customtkinter.CTk()
    ventana_validacion.title("Validación de Dominios/IP")
    ventana_validacion.geometry("1000x700")
    
    # Frame para controles laterales
    frame_controles = customtkinter.CTkFrame(ventana_validacion, width=220)
    frame_controles.pack(side="left", fill="y", padx=10, pady=10)
    
    # Frame principal
    frame_principal = customtkinter.CTkFrame(ventana_validacion)
    frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)
    
    # Información de análisis
    info_frame = customtkinter.CTkFrame(frame_controles)
    info_frame.pack(pady=10, fill="x")
    
    info_label = customtkinter.CTkLabel(info_frame, text="Información de análisis", font=("Arial", 14))
    info_label.pack(pady=5)
    
    global info_stats_label
    info_stats_label = customtkinter.CTkLabel(
        info_frame, 
        text="Dominios: 0\nSeguros: 0\nMaliciosos: 0\nErrores: 0",
        font=("Arial", 12),
        wraplength=180
    )
    info_stats_label.pack(pady=5)
    
    # Botones de control
    control_frame = customtkinter.CTkFrame(frame_controles)
    control_frame.pack(pady=10, fill="x")
    
    btn_importar = customtkinter.CTkButton(
        control_frame,
        text="Importar archivo",
        command=lambda: importar_archivo_validacion(resultados_textbox, info_stats_label, frame_graficos),
        width=200
    )
    btn_importar.pack(pady=5)
    
    btn_guardar = customtkinter.CTkButton(
        control_frame,
        text="Guardar resultados",
        command=lambda: guardar_resultados_validacion(resultados_textbox),
        width=200
    )
    btn_guardar.pack(pady=5)
    
    btn_grafico = customtkinter.CTkButton(
        control_frame,
        text="Mostrar gráfico",
        command=lambda: mostrar_grafico_interactivo(resultados_textbox),
        width=200,
        fg_color="#6a0dad",
        hover_color="#4b0082"
    )
    btn_grafico.pack(pady=5)
    
    btn_firewall = customtkinter.CTkButton(
        control_frame,
        text="Agregar al firewall",
        command=lambda: agregar_al_firewall(resultados_textbox),
        width=200
    )
    btn_firewall.pack(pady=5)
    
    # Área de resultados
    resultados_frame = customtkinter.CTkFrame(frame_principal)
    resultados_frame.pack(expand=True, fill="both", padx=10, pady=10)
    
    resultados_textbox = customtkinter.CTkTextbox(
        resultados_frame,
        wrap="word",
        font=("Consolas", 12)
    )
    resultados_textbox.pack(expand=True, fill="both")
    
    # Frame para gráficos
    frame_graficos = customtkinter.CTkFrame(frame_principal, height=200)
    frame_graficos.pack(fill="x", padx=10, pady=5)
    
    # Configurar tags para colores
    resultados_textbox.tag_config("safe", foreground="green")
    resultados_textbox.tag_config("malicious", foreground="red")
    resultados_textbox.tag_config("error", foreground="orange")
    resultados_textbox.tag_config("info", foreground="blue")
    resultados_textbox.tag_config("spamhaus", foreground="purple")
    
    # Botón de regreso
    btn_volver = customtkinter.CTkButton(
        frame_controles,
        text="Volver",
        command=lambda: cerrar_validacion(ventana_validacion, admin_window),
        width=200
    )
    btn_volver.pack(pady=20)
    
    # Mostrar instrucciones
    resultados_textbox.insert("end", "Instrucciones:\n", "info")
    resultados_textbox.insert("end", "1. Importe un archivo TXT con dominios/IPs\n")
    resultados_textbox.insert("end", "2. Los resultados mostrarán análisis de VirusTotal y Spamhaus\n")
    resultados_textbox.insert("end", "3. Use los botones para guardar o visualizar gráficos\n\n", "info")
    
    ventana_validacion.protocol("WM_DELETE_WINDOW", lambda: cerrar_validacion(ventana_validacion, admin_window))
    ventana_validacion.mainloop()

# ================== FUNCIONES DE INTERFAZ ==================
def importar_archivo_validacion(text_widget, stats_label, graph_frame):
    archivo = filedialog.askopenfilename(
        title="Seleccionar archivo", 
        filetypes=[("Archivos de texto", "*.txt")]
    )
    
    if archivo:
        text_widget.delete("1.0", "end")
        text_widget.insert("end", f"[🔍] Analizando archivo: {archivo}\n\n", "info")
        
        dominios = leer_dominios(archivo)
        if not dominios:
            text_widget.insert("end", "[❌] No hay dominios válidos para analizar\n", "error")
            return
        
        # Mostrar resumen inicial
        total = len(dominios)
        unicos = len(set(dominios))
        repetidos = total - unicos
        
        text_widget.insert("end", f"Resumen del archivo:\n", "info")
        text_widget.insert("end", f"- Total de entradas: {total}\n")
        text_widget.insert("end", f"- Entradas únicas: {unicos}\n")
        text_widget.insert("end", f"- Entradas repetidas: {repetidos}\n\n", "info")
        
        # Analizar dominios
        analizar_dominios(archivo, text_widget, stats_label, graph_frame)

def analizar_dominios(archivo, text_widget, stats_label, graph_frame):
    dominios = leer_dominios(archivo)
    if not dominios:
        text_widget.insert("end", "[❌] No hay dominios para analizar.\n", "error")
        return

    seguros = 0
    maliciosos = 0
    errores = 0

    with ThreadPoolExecutor(max_workers=4) as executor:
        for resultado, tipo in executor.map(verificar_dominio, dominios):
            if tipo == "safe":
                seguros += 1
                tag = "safe"
            elif tipo == "malicious":
                maliciosos += 1
                tag = "malicious"
            else:
                errores += 1
                tag = "error"
            
            text_widget.insert("end", resultado, tag)
            text_widget.see("end")
            text_widget.update()

    # Actualizar estadísticas
    stats_label.configure(text=f"Dominios: {len(dominios)}\nSeguros: {seguros}\nMaliciosos: {maliciosos}\nErrores: {errores}")
    
    # Mostrar gráfico
    mostrar_grafico_basico(seguros, maliciosos, errores, graph_frame)

def mostrar_grafico_basico(seguros, maliciosos, errores, frame):
    # Limpiar frame anterior
    for widget in frame.winfo_children():
        widget.destroy()
    
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(["Seguros", "Maliciosos", "Errores"], [seguros, maliciosos, errores], 
           color=["green", "red", "orange"])
    ax.set_title("Resumen de Análisis")
    
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True)

def mostrar_grafico_interactivo(text_widget):
    contenido = text_widget.get("1.0", "end")
    seguros = contenido.count("[✅]")
    maliciosos = contenido.count("[⚠️]")
    errores = contenido.count("[❌]") - contenido.count("Error Spamhaus")
    
    data = {
        "Categoría": ["Seguros", "Maliciosos", "Errores"],
        "Cantidad": [seguros, maliciosos, errores]
    }
    
    fig = px.pie(data, names="Categoría", values="Cantidad", 
                 title="Distribución de Dominios",
                 color="Categoría",
                 color_discrete_map={"Seguros":"green", "Maliciosos":"red", "Errores":"orange"})
    
    # Guardar temporalmente y abrir en navegador
    temp_file = os.path.join(tempfile.gettempdir(), "grafico_dominios.html")
    fig.write_html(temp_file)
    webbrowser.open(f"file://{temp_file}")

def guardar_resultados_validacion(text_widget):
    resultados = text_widget.get("1.0", "end").strip()
    if not resultados:
        messagebox.showwarning("Advertencia", "No hay resultados para guardar")
        return
    
    archivo = filedialog.asksaveasfilename(
        title="Guardar resultados",
        defaultextension=".txt",
        filetypes=[("Archivos de texto", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
    )
    
    if archivo:
        try:
            if archivo.endswith(".csv"):
                import csv
                lineas = [line.strip() for line in resultados.split("\n") if line.strip()]
                with open(archivo, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Dominio", "Estado"])
                    for linea in lineas:
                        if linea.startswith(("[✅]", "[⚠️]", "[❌]")):
                            estado = "Seguro" if "[✅]" in linea else "Malicioso" if "[⚠️]" in linea else "Error"
                            dominio = linea.split("] ")[1].split(" - ")[0]
                            writer.writerow([dominio, estado])
            elif archivo.endswith(".json"):
                import json
                lineas = [line.strip() for line in resultados.split("\n") if line.strip()]
                data = []
                for linea in lineas:
                    if linea.startswith(("[✅]", "[⚠️]", "[❌]")):
                        estado = "Seguro" if "[✅]" in linea else "Malicioso" if "[⚠️]" in linea else "Error"
                        dominio = linea.split("] ")[1].split(" - ")[0]
                        data.append({"dominio": dominio, "estado": estado})
                with open(archivo, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(archivo, "w") as f:
                    f.write(resultados)
            
            text_widget.insert("end", f"\n[✅] Resultados guardados en {archivo}\n", "info")
        except Exception as e:
            text_widget.insert("end", f"\n[❌] Error al guardar: {str(e)}\n", "error")

def agregar_al_firewall(text_widget):
    contenido = text_widget.get("1.0", "end")
    lineas_maliciosas = [line for line in contenido.split("\n") if "[⚠️]" in line]
    
    if lineas_maliciosas:
        dominios_maliciosos = [line.split(" - ")[0].replace("[⚠️] ", "") for line in lineas_maliciosas]
        text_widget.insert("end", "\nDominios para bloquear:\n", "info")
        for dominio in dominios_maliciosos:
            text_widget.insert("end", f"- {dominio}\n")
    else:
        text_widget.insert("end", "\nNo se encontraron dominios maliciosos para bloquear\n", "info")

# ================== INTERFAZ PRINCIPAL ==================
def abrir_interfaz_admin(login_window):
    login_window.destroy()

    ventana_admin = customtkinter.CTk()
    ventana_admin.title("Interfaz de Administrador")
    ventana_admin.geometry("900x650")

    frame_botones = customtkinter.CTkFrame(ventana_admin, width=220)
    frame_botones.pack(side="left", fill="y", padx=10, pady=10)

    frame_principal = customtkinter.CTkFrame(ventana_admin)
    frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)

    # Descripción/ayuda
    frame_descripcion = customtkinter.CTkFrame(frame_principal)
    frame_descripcion.pack(fill="x", padx=5, pady=5)

    descripcion_label = customtkinter.CTkLabel(
        frame_descripcion, 
        text="Seleccione una opción del menú",
        font=("Arial", 12),
        wraplength=500
    )
    descripcion_label.pack(pady=10)

    # Contenido dinámico
    frame_contenido = customtkinter.CTkFrame(frame_principal)
    frame_contenido.pack(expand=True, fill="both", padx=5, pady=5)

    def mostrar_descripcion(texto):
        descripcion_label.configure(text=texto)

    def limpiar_descripcion(event=None):
        descripcion_label.configure(text="Seleccione una opción del menú")

    def limpiar_contenido():
        for widget in frame_contenido.winfo_children():
            widget.destroy()

    def mostrar_importar_txt():
        limpiar_contenido()
        
        frame_acciones = customtkinter.CTkFrame(frame_contenido)
        frame_acciones.pack(fill="x", padx=5, pady=5)
        
        boton_examinar = customtkinter.CTkButton(
            frame_acciones,
            text="Examinar archivo TXT",
            command=lambda: cargar_archivo_txt(),
            width=200
        )
        boton_examinar.pack(side="left", padx=5)
        
        boton_limpiar = customtkinter.CTkButton(
            frame_acciones,
            text="Limpiar",
            command=lambda: limpiar_resultados(),
            width=200
        )
        boton_limpiar.pack(side="left", padx=5)
        
        boton_guardar_procesado = customtkinter.CTkButton(
            frame_acciones,
            text="Guardar limpio",
            command=lambda: guardar_archivo_procesado(),
            fg_color="#2aa44f",
            hover_color="#1d7a3b",
            width=200
        )
        boton_guardar_procesado.pack(side="left", padx=5)
        
        global frame_resultados
        frame_resultados = customtkinter.CTkFrame(frame_contenido)
        frame_resultados.pack(expand=True, fill="both", padx=5, pady=5)
        
        tabview = customtkinter.CTkTabview(frame_resultados)
        tabview.pack(expand=True, fill="both")
        
        global tabs, dominios_actuales
        dominios_actuales = []
        tabs = {
            "contenido": tabview.add("Contenido"),
            "repetidos": tabview.add("Repetidos"),
            "estadisticas": tabview.add("Estadísticas")
        }
        
        for tab in tabs.values():
            scroll = customtkinter.CTkScrollableFrame(tab)
            scroll.pack(expand=True, fill="both")
            
            label = customtkinter.CTkLabel(scroll, text="No hay datos para mostrar", wraplength=500)
            label.pack(pady=10)
            
            setattr(tab, "content_label", label)

    def cargar_archivo_txt():
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo TXT",
            filetypes=[("Archivos de texto", "*.txt")]
        )
        
        if archivo:
            try:
                with open(archivo, 'r') as f:
                    lineas = [line.strip() for line in f.readlines() if line.strip()]
                
                if not lineas:
                    messagebox.showwarning("Advertencia", "El archivo está vacío")
                    return
                
                global dominios_actuales
                dominios_actuales = lineas
                
                total = len(lineas)
                contador = Counter(lineas)
                repetidos = {k: v for k, v in contador.items() if v > 1}
                unicos = len(contador)
                
                contenido_texto = "\n".join(lineas)
                tabs["contenido"].content_label.configure(
                    text=f"Total de entradas: {total}\n\nContenido:\n{contenido_texto}",
                    justify="left"
                )
                
                if repetidos:
                    repetidos_texto = "\n".join([f"{k} (repetido {v} veces)" for k, v in repetidos.items()])
                    tabs["repetidos"].content_label.configure(
                        text=f"Entradas repetidas ({len(repetidos)}):\n\n{repetidos_texto}",
                        justify="left"
                    )
                else:
                    tabs["repetidos"].content_label.configure(
                        text="No se encontraron entradas repetidas",
                        justify="left"
                    )
                
                stats_text = (
                    f"Total de entradas: {total}\n"
                    f"Entradas únicas: {unicos}\n"
                    f"Entradas repetidas: {len(repetidos)}\n"
                    f"Porcentaje de duplicados: {len(repetidos)/unicos*100:.2f}%"
                )
                tabs["estadisticas"].content_label.configure(
                    text=stats_text,
                    justify="left"
                )
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {str(e)}")

    def limpiar_resultados():
        for tab in tabs.values():
            tab.content_label.configure(text="No hay datos para mostrar")
        global dominios_actuales
        dominios_actuales = []

    def guardar_archivo_procesado():
        if not dominios_actuales:
            messagebox.showwarning("Advertencia", "No hay datos para guardar")
            return
        
        dominios_procesados = set()
        
        for dominio in dominios_actuales:
            dominio_limpio = dominio.lower().strip()
            
            if dominio_limpio.startswith(('http://', 'https://')):
                dominio_limpio = dominio_limpio.split('://')[1]
            
            if dominio_limpio.startswith('www.'):
                dominio_limpio = dominio_limpio[4:]
            
            dominio_limpio = dominio_limpio.split('/')[0].split('?')[0].split(':')[0]
            
            if dominio_limpio and '.' in dominio_limpio:
                dominios_procesados.add(dominio_limpio)
        
        if not dominios_procesados:
            messagebox.showwarning("Advertencia", "No se encontraron dominios válidos para guardar")
            return
        
        archivo = filedialog.asksaveasfilename(
            title="Guardar dominios procesados",
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json")]
        )
        
        if archivo:
            try:
                if archivo.endswith(".csv"):
                    import csv
                    with open(archivo, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Dominio"])
                        for dominio in sorted(dominios_procesados):
                            writer.writerow([dominio])
                elif archivo.endswith(".json"):
                    import json
                    with open(archivo, 'w') as f:
                        json.dump(sorted(list(dominios_procesados)), f, indent=2)
                else:
                    with open(archivo, 'w') as f:
                        f.write('\n'.join(sorted(dominios_procesados)))
                
                messagebox.showinfo("Éxito", f"Dominios guardados en {archivo}")
                
                tabs["estadisticas"].content_label.configure(
                    text=f"Dominios únicos guardados: {len(dominios_procesados)}\n\n" +
                         "Ejemplos:\n" + '\n'.join(sorted(dominios_procesados)[:5]) + 
                         ("\n..." if len(dominios_procesados) > 5 else ""),
                    justify="left"
                )
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")

    # Botones principales
    botones = [
        ("Importar txt", "Importar y analizar archivos TXT con dominios/IPs", mostrar_importar_txt),
        ("Verificar db", "Verificar la integridad de la base de datos", lambda: limpiar_contenido()),
        ("Validar txt", "Validar dominios/ips con VirusTotal y Spamhaus", lambda: abrir_app_validacion(ventana_admin))
    ]

    for texto_boton, descripcion, comando in botones:
        boton = customtkinter.CTkButton(
            frame_botones, 
            text=texto_boton,
            command=comando,
            width=200
        )
        boton.pack(pady=5, padx=10, fill="x")
        
        boton.bind("<Enter>", lambda event, desc=descripcion: mostrar_descripcion(desc))
        boton.bind("<Leave>", limpiar_descripcion)

    ventana_admin.mainloop()

# ================== FUNCIONES AUXILIARES ==================
def cerrar_validacion(validacion_window, admin_window):
    validacion_window.destroy()
    if admin_window:
        admin_window.deiconify()

# ================== INTERFAZ DE LOGIN ==================
def login():
    nombre = entrada_usuario.get()
    contraseña = entrada_contraseña.get()
    rol = "administrador"

    if rol == "administrador":
        etiqueta_resultado.configure(text=f"Bienvenido, {nombre}. Rol: Administrador", text_color="green")
        abrir_interfaz_admin(app)  
    elif rol:
        etiqueta_resultado.configure(text=f"Bienvenido, {nombre}. Rol: {rol}", text_color="blue")
    else:
        etiqueta_resultado.configure(text="Credenciales incorrectas.", text_color="red")

# ================== CONFIGURACIÓN INICIAL ==================
customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("400x300")
app.title("Sistema de Login")

etiqueta_usuario = customtkinter.CTkLabel(app, text="Usuario:")
etiqueta_usuario.pack(pady=10)
entrada_usuario = customtkinter.CTkEntry(app)
entrada_usuario.pack(pady=10)

etiqueta_contraseña = customtkinter.CTkLabel(app, text="Contraseña:")
etiqueta_contraseña.pack(pady=10)
entrada_contraseña = customtkinter.CTkEntry(app, show="*")
entrada_contraseña.pack(pady=10)

boton_login = customtkinter.CTkButton(app, text="Login", command=login)
boton_login.pack(pady=10)

etiqueta_resultado = customtkinter.CTkLabel(app, text="")
etiqueta_resultado.pack(pady=10)

app.mainloop()

import customtkinter
from tkinter import filedialog, messagebox
from collections import Counter
import webbrowser
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from socket import gethostbyname, gaierror
import pandas as pd
import plotly.express as px
import tempfile
import os
import sys
import sqlite3
from hashlib import sha256
from validar import AppValidacion
from pyqt import *

# ================== INTERFAZ ROOT (SUPERUSUARIO) ==================
class AppRoot(customtkinter.CTk):
    def __init__(self, login_window, username):
        super().__init__()
        self.login_window = login_window
        self.username = username
        
        self.title(f"Interfaz Root - {username}")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Configuración inicial de la base de datos
        self.inicializar_base_reportes()
        self.setup_ui()
        self.mainloop()
    
    def inicializar_base_reportes(self):
        """Crea la base de datos para almacenar reportes si no existe"""
        conexion = sqlite3.connect('reportes.db')
        cursor = conexion.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reportes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            usuario TEXT NOT NULL,
            tipo TEXT NOT NULL,
            contenido TEXT NOT NULL,
            resultado TEXT NOT NULL
        )
        ''')
        
        conexion.commit()
        conexion.close()
    
    def setup_ui(self):
        # Frame principal con dos columnas
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Frame de navegación (izquierda)
        self.frame_navegacion = customtkinter.CTkFrame(self, width=200, corner_radius=0)
        self.frame_navegacion.grid(row=0, column=0, sticky="nsew")
        self.frame_navegacion.grid_rowconfigure(6, weight=1)
        
        # Frame de contenido (derecha)
        self.frame_contenido = customtkinter.CTkFrame(self, corner_radius=0)
        self.frame_contenido.grid(row=0, column=1, sticky="nsew")
        self.frame_contenido.grid_rowconfigure(0, weight=1)
        self.frame_contenido.grid_columnconfigure(0, weight=1)
        
        # Barra superior con información de usuario
        self.frame_superior = customtkinter.CTkFrame(self.frame_contenido, height=50)
        self.frame_superior.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        self.label_usuario = customtkinter.CTkLabel(
            self.frame_superior, 
            text=f"Usuario ROOT: {self.username}",
            font=("Arial", 14, "bold")
        )
        self.label_usuario.pack(side="left", padx=20)
        
        boton_cerrar_sesion = customtkinter.CTkButton(
            self.frame_superior,
            text="Cerrar sesión",
            command=self.cerrar_sesion,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cerrar_sesion.pack(side="right", padx=20)
        
        # Botones de navegación
        botones_nav = [
            ("📊 Dashboard", self.mostrar_dashboard),
            ("📈 Gráficos", self.mostrar_graficos),
            ("📋 Reportes", self.mostrar_reportes),
            ("👥 Usuarios", self.mostrar_usuarios),
            ("⚙️ Configuración", self.mostrar_configuracion)
        ]
        
        for i, (texto, comando) in enumerate(botones_nav):
            boton = customtkinter.CTkButton(
                self.frame_navegacion,
                text=texto,
                command=comando,
                height=40,
                anchor="w",
                font=("Arial", 14),
                corner_radius=0
            )
            boton.grid(row=i, column=0, sticky="ew", padx=5, pady=5)
        
        self.mostrar_dashboard()
    
    def limpiar_contenido(self):
        """Limpia el frame de contenido"""
        for widget in self.frame_contenido.winfo_children():
            if widget != self.frame_superior:
                widget.destroy()
    
    def mostrar_dashboard(self):
        """Muestra el panel principal con resumen de actividad"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(0, weight=1)
        
        stats = self.obtener_estadisticas()
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Dashboard Root - Resumen del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.grid(row=0, column=0, pady=20, sticky="n")
        
        frame_metricas = customtkinter.CTkFrame(frame_principal)
        frame_metricas.grid(row=1, column=0, pady=10, sticky="nsew")
        
        metricas = [
            ("📊 Reportes totales", stats['total_reportes']),
            ("👥 Usuarios registrados", stats['total_usuarios']),
            ("⚠️ Alertas recientes", stats['alertas_7dias']),
            ("🔄 Última actividad", stats['ultima_actividad'])
        ]
        
        for i, (titulo, valor) in enumerate(metricas):
            frame_metrica = customtkinter.CTkFrame(frame_metricas)
            frame_metrica.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")
            
            label_titulo = customtkinter.CTkLabel(
                frame_metrica,
                text=titulo,
                font=("Arial", 12)
            )
            label_titulo.pack(pady=(10, 0))
            
            label_valor = customtkinter.CTkLabel(
                frame_metrica,
                text=str(valor),
                font=("Arial", 24, "bold")
            )
            label_valor.pack(pady=(0, 10))
    
    def mostrar_graficos(self):
        """Muestra gráficos de actividad reciente"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Visualización de Gráficos",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener datos para gráficos
        datos = self.obtener_datos_graficos()
        
        # Gráfico 1: Actividad por usuario
        fig1, ax1 = plt.subplots(figsize=(8, 4))
        datos['actividad_usuarios'].plot(kind='bar', ax=ax1, color='skyblue')
        ax1.set_title('Actividad por Usuario (últimos 30 días)')
        ax1.set_ylabel('Número de acciones')
        
        canvas1 = FigureCanvasTkAgg(fig1, master=frame_principal)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
        
        # Gráfico 2: Tipos de reportes
        fig2, ax2 = plt.subplots(figsize=(8, 4))
        datos['tipos_reportes'].plot(kind='pie', autopct='%1.1f%%', ax=ax2)
        ax2.set_title('Distribución de Tipos de Reportes')
        ax2.set_ylabel('')
        
        canvas2 = FigureCanvasTkAgg(fig2, master=frame_principal)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
    
    def mostrar_reportes(self):
        """Muestra el historial de reportes generados"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Historial de Reportes",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener reportes de la base de datos
        reportes = self.obtener_ultimos_reportes()
        
        # Crear tabla de reportes
        frame_tabla = customtkinter.CTkScrollableFrame(frame_principal)
        frame_tabla.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Encabezados de la tabla
        encabezados = ["ID", "Fecha", "Usuario", "Tipo", "Acciones"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                frame_tabla,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados)-1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")
        
        # Filas con datos
        for i, reporte in enumerate(reportes, start=1):
            for j, campo in enumerate(reporte[:4]):  # Mostrar solo los primeros 4 campos
                label = customtkinter.CTkLabel(
                    frame_tabla,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")
            
            # Botón para ver detalles
            boton_ver = customtkinter.CTkButton(
                frame_tabla,
                text="Ver Detalles",
                command=lambda r=reporte: self.mostrar_detalle_reporte(r),
                width=100
            )
            boton_ver.grid(row=i, column=4, padx=5, pady=5)
    
    def mostrar_usuarios(self):
        """Muestra la gestión de usuarios del sistema"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Gestión de Usuarios",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Obtener lista de usuarios
        usuarios = self.obtener_usuarios()
        
        # Crear tabla de usuarios
        frame_tabla = customtkinter.CTkScrollableFrame(frame_principal, height=300)
        frame_tabla.pack(fill="x", padx=20, pady=10)
        
        # Encabezados de la tabla
        encabezados = ["ID", "Nombre", "Rol", "Acciones"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                frame_tabla,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados)-1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")
        
        # Filas con datos
        for i, usuario in enumerate(usuarios, start=1):
            for j, campo in enumerate(usuario[:3]):  # Mostrar id, nombre y rol
                label = customtkinter.CTkLabel(
                    frame_tabla,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")
            
            # Botones de acción
            frame_botones = customtkinter.CTkFrame(frame_tabla, fg_color="transparent")
            frame_botones.grid(row=i, column=3, padx=5, pady=5, sticky="e")
            
            boton_editar = customtkinter.CTkButton(
                frame_botones,
                text="Editar",
                command=lambda u=usuario: self.editar_usuario(u),
                width=80
            )
            boton_editar.pack(side="left", padx=2)
            
            boton_eliminar = customtkinter.CTkButton(
                frame_botones,
                text="Eliminar",
                command=lambda u=usuario: self.eliminar_usuario(u),
                width=80,
                fg_color="#d9534f",
                hover_color="#c9302c"
            )
            boton_eliminar.pack(side="left", padx=2)
        
        # Botón para agregar nuevo usuario
        boton_nuevo = customtkinter.CTkButton(
            frame_principal,
            text="+ Agregar Usuario",
            command=self.agregar_usuario,
            fg_color="#5cb85c",
            hover_color="#4cae4c",
            height=40,
            width=200
        )
        boton_nuevo.pack(pady=20)
    
    # ========== FUNCIONES DE DATOS ==========
    def obtener_estadisticas(self):
        """Obtiene estadísticas del sistema para el dashboard"""
        conn = sqlite3.connect('reportes.db')
        cursor = conn.cursor()
        
        # Obtener total de reportes
        cursor.execute("SELECT COUNT(*) FROM reportes")
        total_reportes = cursor.fetchone()[0]
        
        # Obtener total de usuarios
        conn_usuarios = sqlite3.connect('usuarios.db')
        cursor_usuarios = conn_usuarios.cursor()
        cursor_usuarios.execute("SELECT COUNT(*) FROM usuarios")
        total_usuarios = cursor_usuarios.fetchone()[0]
        conn_usuarios.close()
        
        # Obtener alertas recientes
        cursor.execute("""
            SELECT COUNT(*) FROM reportes 
            WHERE fecha >= datetime('now', '-7 days')
            AND resultado LIKE '%malicioso%' OR resultado LIKE '%sospechoso%'
        """)
        alertas_7dias = cursor.fetchone()[0]
        
        # Obtener última actividad
        cursor.execute("SELECT MAX(fecha) FROM reportes")
        ultima_actividad = cursor.fetchone()[0] or "Ninguna"
        
        conn.close()
        
        return {
            'total_reportes': total_reportes,
            'total_usuarios': total_usuarios,
            'alertas_7dias': alertas_7dias,
            'ultima_actividad': ultima_actividad
        }
    
    def obtener_datos_graficos(self):
        """Obtiene datos para generar gráficos"""
        conn = sqlite3.connect('reportes.db')
        
        # Actividad por usuario
        df_actividad = pd.read_sql("""
            SELECT usuario, COUNT(*) as acciones 
            FROM reportes 
            WHERE fecha >= datetime('now', '-30 days')
            GROUP BY usuario
            ORDER BY acciones DESC
            LIMIT 10
        """, conn)
        
        # Tipos de reportes
        df_tipos = pd.read_sql("""
            SELECT tipo, COUNT(*) as cantidad
            FROM reportes
            GROUP BY tipo
        """, conn)
        
        conn.close()
        
        return {
            'actividad_usuarios': df_actividad.set_index('usuario')['acciones'],
            'tipos_reportes': df_tipos.set_index('tipo')['cantidad']
        }
    
    def obtener_ultimos_reportes(self, limite=20):
        """Obtiene los últimos reportes generados"""
        conn = sqlite3.connect('reportes.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, fecha, tipo, contenido, resultado
            FROM reportes
            ORDER BY fecha DESC
            LIMIT ?
        ''', (limite,))
        
        reportes = cursor.fetchall()
        conn.close()
        return reportes
    
    def obtener_usuarios(self):
        """Obtiene la lista de usuarios del sistema"""
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, nombre, rol FROM usuarios ORDER BY nombre")
        usuarios = cursor.fetchall()
        conn.close()
        return usuarios
    
    # ========== FUNCIONES DE INTERACCIÓN ==========
    def mostrar_detalle_reporte(self, reporte):
        """Muestra los detalles completos de un reporte"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title(f"Detalle Reporte #{reporte[0]}")
        ventana.geometry("800x600")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Mostrar información básica
        info_basica = f"""
        ID: {reporte[0]}
        Fecha: {reporte[1]}
        Usuario: {reporte[2]}
        Tipo: {reporte[3]}
        """
        
        label_info = customtkinter.CTkLabel(
            frame_principal,
            text=info_basica,
            font=("Arial", 14),
            justify="left"
        )
        label_info.pack(pady=10, padx=20, anchor="w")
        
        # Mostrar contenido con scroll
        label_contenido = customtkinter.CTkLabel(
            frame_principal,
            text="Contenido:",
            font=("Arial", 12, "bold")
        )
        label_contenido.pack(pady=(10, 0), padx=20, anchor="w")
        
        texto_contenido = customtkinter.CTkTextbox(
            frame_principal,
            wrap="word",
            height=150
        )
        texto_contenido.insert("1.0", reporte[4])
        texto_contenido.configure(state="disabled")
        texto_contenido.pack(fill="x", padx=20, pady=(0, 10))
        
        # Mostrar resultado con scroll
        label_resultado = customtkinter.CTkLabel(
            frame_principal,
            text="Resultado:",
            font=("Arial", 12, "bold")
        )
        label_resultado.pack(pady=(10, 0), padx=20, anchor="w")
        
        texto_resultado = customtkinter.CTkTextbox(
            frame_principal,
            wrap="word",
            height=150
        )
        texto_resultado.insert("1.0", reporte[5])
        texto_resultado.configure(state="disabled")
        texto_resultado.pack(fill="x", padx=20, pady=(0, 10))
        
        # Botón para cerrar
        boton_cerrar = customtkinter.CTkButton(
            frame_principal,
            text="Cerrar",
            command=ventana.destroy
        )
        boton_cerrar.pack(pady=10)
    
    def editar_usuario(self, usuario):
        """Abre ventana para editar usuario"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title(f"Editar Usuario #{usuario[0]}")
        ventana.geometry("400x300")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Campos del formulario
        label_nombre = customtkinter.CTkLabel(frame_principal, text="Nombre:")
        label_nombre.pack(pady=(10, 0))
        
        entrada_nombre = customtkinter.CTkEntry(frame_principal, width=300)
        entrada_nombre.insert(0, usuario[1])
        entrada_nombre.pack(pady=5)
        
        label_rol = customtkinter.CTkLabel(frame_principal, text="Rol:")
        label_rol.pack(pady=(10, 0))
        
        opciones_rol = ["root", "administrador", "usuario"]
        combo_rol = customtkinter.CTkComboBox(
            frame_principal,
            values=opciones_rol,
            width=300
        )
        combo_rol.set(usuario[2])
        combo_rol.pack(pady=5)
        
        label_password = customtkinter.CTkLabel(frame_principal, text="Nueva contraseña (opcional):")
        label_password.pack(pady=(10, 0))
        
        entrada_password = customtkinter.CTkEntry(frame_principal, width=300, show="*")
        entrada_password.pack(pady=5)
        
        # Botones de acción
        frame_botones = customtkinter.CTkFrame(frame_principal, fg_color="transparent")
        frame_botones.pack(pady=20)
        
        boton_guardar = customtkinter.CTkButton(
            frame_botones,
            text="Guardar",
            command=lambda: self.guardar_cambios_usuario(
                usuario[0],
                entrada_nombre.get(),
                combo_rol.get(),
                entrada_password.get(),
                ventana
            ),
            width=120
        )
        boton_guardar.pack(side="left", padx=10)
        
        boton_cancelar = customtkinter.CTkButton(
            frame_botones,
            text="Cancelar",
            command=ventana.destroy,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cancelar.pack(side="right", padx=10)
    
    def guardar_cambios_usuario(self, id_usuario, nombre, rol, password, ventana):
        """Guarda los cambios del usuario en la base de datos"""
        if not nombre or not rol:
            messagebox.showerror("Error", "Nombre y rol son obligatorios")
            return
        
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        try:
            if password:  # Si se proporcionó nueva contraseña
                password_hash = sha256(password.encode()).hexdigest()
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, contraseña=?, rol=?
                    WHERE id=?
                """, (nombre, password_hash, rol, id_usuario))
            else:  # Mantener la contraseña actual
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, rol=?
                    WHERE id=?
                """, (nombre, rol, id_usuario))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario actualizado correctamente")
            ventana.destroy()
            self.mostrar_usuarios()  # Refrescar la lista
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo actualizar el usuario: {str(e)}")
        finally:
            conn.close()
    
    def eliminar_usuario(self, usuario):
        """Elimina un usuario del sistema"""
        if usuario[1] == self.username:
            messagebox.showerror("Error", "No puedes eliminarte a ti mismo")
            return
        
        confirmacion = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Estás seguro de eliminar al usuario {usuario[1]}? Esta acción no se puede deshacer."
        )
        
        if confirmacion:
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()
            
            try:
                cursor.execute("DELETE FROM usuarios WHERE id=?", (usuario[0],))
                conn.commit()
                messagebox.showinfo("Éxito", "Usuario eliminado correctamente")
                self.mostrar_usuarios()  # Refrescar la lista
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar el usuario: {str(e)}")
            finally:
                conn.close()
    
    def agregar_usuario(self):
        """Abre ventana para agregar nuevo usuario"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title("Agregar Nuevo Usuario")
        ventana.geometry("400x300")
        
        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Campos del formulario
        label_nombre = customtkinter.CTkLabel(frame_principal, text="Nombre de usuario:")
        label_nombre.pack(pady=(10, 0))
        
        entrada_nombre = customtkinter.CTkEntry(frame_principal, width=300)
        entrada_nombre.pack(pady=5)
        
        label_password = customtkinter.CTkLabel(frame_principal, text="Contraseña:")
        label_password.pack(pady=(10, 0))
        
        entrada_password = customtkinter.CTkEntry(frame_principal, width=300, show="*")
        entrada_password.pack(pady=5)
        
        label_rol = customtkinter.CTkLabel(frame_principal, text="Rol:")
        label_rol.pack(pady=(10, 0))
        
        opciones_rol = ["root", "administrador", "usuario"]
        combo_rol = customtkinter.CTkComboBox(
            frame_principal,
            values=opciones_rol,
            width=300
        )
        combo_rol.set("usuario")
        combo_rol.pack(pady=5)
        
        # Botones de acción
        frame_botones = customtkinter.CTkFrame(frame_principal, fg_color="transparent")
        frame_botones.pack(pady=20)
        
        boton_guardar = customtkinter.CTkButton(
            frame_botones,
            text="Guardar",
            command=lambda: self.crear_nuevo_usuario(
                entrada_nombre.get(),
                entrada_password.get(),
                combo_rol.get(),
                ventana
            ),
            width=120
        )
        boton_guardar.pack(side="left", padx=10)
        
        boton_cancelar = customtkinter.CTkButton(
            frame_botones,
            text="Cancelar",
            command=ventana.destroy,
            width=120,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cancelar.pack(side="right", padx=10)
    
    def crear_nuevo_usuario(self, nombre, password, rol, ventana):
        """Crea un nuevo usuario en la base de datos"""
        if not nombre or not password or not rol:
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
        
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()
        
        try:
            # Verificar si el usuario ya existe
            cursor.execute("SELECT id FROM usuarios WHERE nombre=?", (nombre,))
            if cursor.fetchone():
                messagebox.showerror("Error", "El nombre de usuario ya existe")
                return
            
            # Crear hash de la contraseña
            password_hash = sha256(password.encode()).hexdigest()
            
            # Insertar nuevo usuario
            cursor.execute("""
                INSERT INTO usuarios (nombre, contraseña, rol)
                VALUES (?, ?, ?)
            """, (nombre, password_hash, rol))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario creado correctamente")
            ventana.destroy()
            self.mostrar_usuarios()  # Refrescar la lista
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el usuario: {str(e)}")
        finally:
            conn.close()
    
    def mostrar_configuracion(self):
        """Muestra la configuración del sistema"""
        self.limpiar_contenido()
        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Configuración del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)
        
        # Aquí podrías añadir opciones de configuración como:
        # - Tema de la interfaz (oscuro/claro)
        # - Configuración de APIs
        # - Preferencias de notificaciones
        # - etc.
        
        label_info = customtkinter.CTkLabel(
            frame_principal,
            text="Configuración avanzada del sistema para usuarios root",
            font=("Arial", 14)
        )
        label_info.pack(pady=10)
    
    def cerrar_sesion(self):
        """Cierra la sesión y vuelve al login"""
        self.destroy()
        self.login_window.deiconify()
    
    def on_close(self):
        """Maneja el cierre de la ventana"""
        self.cerrar_sesion()

class AppLogin(customtkinter.CTk):

    
    def abrir_ventana_principal(self, rol, username):
        if rol == "root":
            self.destroy()
            AppRoot(None, username)  
        elif rol == "administrador":
            self.destroy()
            AppAdmin(None, username)
        else:
            messagebox.showinfo("Acceso", f"Bienvenido usuario {username} (rol: {rol})")

def inicializar_base_datos():
    conexion = sqlite3.connect('usuarios.db')
    cursor = conexion.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        contraseña TEXT NOT NULL,
        rol TEXT NOT NULL
    )
    ''')
    
    cursor.execute("SELECT * FROM usuarios WHERE nombre='admin'")
    if not cursor.fetchone():
        password_hash = sha256('admin123'.encode()).hexdigest()
        cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES (?, ?, ?)", 
                      ('admin', password_hash, 'administrador'))
    
    cursor.execute("SELECT * FROM usuarios WHERE nombre='root'")
    if not cursor.fetchone():
        password_hash = sha256('root123'.encode()).hexdigest()
        cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES (?, ?, ?)", 
                      ('root', password_hash, 'root'))
    
    conexion.commit()
    conexion.close()