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
from root.app import AppRoot

API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
DISCORD_WEBHOOK_URL = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# ================== BASE DE DATOS DE USUARIOS ==================
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
    
    conexion.commit()
    conexion.close()

def verificar_usuario(nombre, contraseña):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    cursor.execute("SELECT rol FROM usuarios WHERE nombre=? AND contraseña=?", (nombre, contraseña))
    resultado = cursor.fetchone()
    conn.close()

    if resultado:
        return resultado[0]  
    return None

# ================== FUNCIONES DE ANÁLISIS ==================
def verificar_dominio(dominio):
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
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

# ================== INTERFAZ DE LOGIN ==================
class AppLogin(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Login")
        self.geometry("400x350")
        self.protocol("WM_DELETE_WINDOW", self.salir)
        inicializar_base_datos()
        self.setup_ui()
    
    def setup_ui(self):
        frame_principal = customtkinter.CTkFrame(self)
        frame_principal.pack(pady=20, padx=20, fill="both", expand=True)
        
        label_titulo = customtkinter.CTkLabel(frame_principal, text="Inicio de Sesión", font=("Arial", 20))
        label_titulo.pack(pady=12, padx=10)
        
        self.entrada_usuario = customtkinter.CTkEntry(frame_principal, placeholder_text="Usuario")
        self.entrada_usuario.pack(pady=12, padx=10)
        
        self.entrada_password = customtkinter.CTkEntry(frame_principal, placeholder_text="Contraseña", show="*")
        self.entrada_password.pack(pady=12, padx=10)
        
        boton_login = customtkinter.CTkButton(frame_principal, text="Iniciar Sesión", command=self.login)
        boton_login.pack(pady=12, padx=10)
        
        boton_salir = customtkinter.CTkButton(frame_principal, text="Salir", command=self.salir, fg_color="#d9534f")
        boton_salir.pack(pady=12, padx=10)
        
        self.etiqueta_resultado = customtkinter.CTkLabel(frame_principal, text="", font=("Arial", 12))
        self.etiqueta_resultado.pack(pady=12, padx=10)
        
        self.entrada_password.bind("<Return>", lambda event: self.login())
    
    def login(self):
        username = self.entrada_usuario.get().strip()
        password = self.entrada_password.get().strip()
        
        if not username or not password:
            self.etiqueta_resultado.configure(text="Usuario y contraseña son requeridos", text_color="red")
            return
        
        rol = verificar_usuario(username, password)
        
        if rol:
            self.etiqueta_resultado.configure(text=f"Bienvenido, {username}", text_color="green")
            self.after(1000, lambda: self.abrir_ventana_principal(rol, username))
        else:
            self.etiqueta_resultado.configure(text="Credenciales incorrectas", text_color="red")
            self.entrada_password.delete(0, 'end')
    
    def abrir_ventana_principal(self, rol, username):
        if rol == "administrador":
            self.destroy()  
            AppAdmin(None, username) 
        elif rol == "root":
            self.destroy()  
            AppRoot(None, username)
        else:
            messagebox.showinfo("Acceso", f"Bienvenido usuario {username} (rol: {rol})")
    
    def salir(self):
        self.destroy()
        sys.exit()

# ================== INTERFAZ PRINCIPAL ==================
class AppAdmin(customtkinter.CTk):
    def __init__(self, login_window, username):
        super().__init__()
        self.login_window = login_window
        self.username = username
        
        self.title(f"Interfaz de Administrador - {username}")
        self.geometry("900x650")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.setup_ui()
        self.mainloop()
    
    def setup_ui(self):
        self.frame_botones = customtkinter.CTkFrame(self, width=220)
        self.frame_botones.pack(side="left", fill="y", padx=10, pady=10)

        self.frame_principal = customtkinter.CTkFrame(self)
        self.frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)

        self.frame_status = customtkinter.CTkFrame(self.frame_principal, height=30)
        self.frame_status.pack(fill="x", padx=5, pady=5)
        
        self.label_usuario = customtkinter.CTkLabel(
            self.frame_status, 
            text=f"Usuario: {self.username} (Administrador)",
            font=("Arial", 12)
        )
        self.label_usuario.pack(side="left", padx=10)
        
        boton_cerrar_sesion = customtkinter.CTkButton(
            self.frame_status,
            text="Cerrar sesión",
            command=self.cerrar_sesion,
            width=100,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cerrar_sesion.pack(side="right", padx=10)

        self.frame_descripcion = customtkinter.CTkFrame(self.frame_principal)
        self.frame_descripcion.pack(fill="x", padx=5, pady=5)

        self.descripcion_label = customtkinter.CTkLabel(
            self.frame_descripcion, 
            text="Seleccione una opción del menú",
            font=("Arial", 12),
            wraplength=500
        )
        self.descripcion_label.pack(pady=10)

        self.frame_contenido = customtkinter.CTkFrame(self.frame_principal)
        self.frame_contenido.pack(expand=True, fill="both", padx=5, pady=5)

        botones = [
            ("Importar txt", "Importar y analizar archivos TXT con dominios/IPs", self.mostrar_importar_txt),
            ("Verificar db", "Verificar la integridad de la base de datos", lambda: self.limpiar_contenido()),
            ("Validar txt", "Validar dominios/ips con VirusTotal y Spamhaus", self.abrir_validacion)
        ]

        for texto_boton, descripcion, comando in botones:
            boton = customtkinter.CTkButton(
                self.frame_botones, 
                text=texto_boton,
                command=comando,
                width=200
            )
            boton.pack(pady=5, padx=10, fill="x")
            
            boton.bind("<Enter>", lambda event, desc=descripcion: self.mostrar_descripcion(desc))
            boton.bind("<Leave>", lambda event: self.limpiar_descripcion())
    
    def mostrar_descripcion(self, texto):
        self.descripcion_label.configure(text=texto)

    def limpiar_descripcion(self):
        self.descripcion_label.configure(text="Seleccione una opción del menú")

    def limpiar_contenido(self):
        for widget in self.frame_contenido.winfo_children():
            widget.destroy()

    def mostrar_importar_txt(self):
        self.limpiar_contenido()
        
        frame_acciones = customtkinter.CTkFrame(self.frame_contenido)
        frame_acciones.pack(fill="x", padx=5, pady=5)
        
        boton_examinar = customtkinter.CTkButton(
            frame_acciones,
            text="Examinar archivo TXT",
            command=lambda: self.cargar_archivo_txt(),
            width=200
        )
        boton_examinar.pack(side="left", padx=5)
        
        boton_limpiar = customtkinter.CTkButton(
            frame_acciones,
            text="Limpiar",
            command=lambda: self.limpiar_resultados(),
            width=200
        )
        boton_limpiar.pack(side="left", padx=5)
        
        boton_guardar_procesado = customtkinter.CTkButton(
            frame_acciones,
            text="Guardar limpio",
            command=lambda: self.guardar_archivo_procesado(),
            fg_color="#2aa44f",
            hover_color="#1d7a3b",
            width=200
        )
        boton_guardar_procesado.pack(side="left", padx=5)
        
        self.frame_resultados = customtkinter.CTkFrame(self.frame_contenido)
        self.frame_resultados.pack(expand=True, fill="both", padx=5, pady=5)
        
        self.tabview = customtkinter.CTkTabview(self.frame_resultados)
        self.tabview.pack(expand=True, fill="both")
        
        self.tabs = {
            "contenido": self.tabview.add("Contenido"),
            "repetidos": self.tabview.add("Repetidos"),
            "estadisticas": self.tabview.add("Estadísticas")
        }
        
        for tab in self.tabs.values():
            scroll = customtkinter.CTkScrollableFrame(tab)
            scroll.pack(expand=True, fill="both")
            
            label = customtkinter.CTkLabel(scroll, text="No hay datos para mostrar", wraplength=500)
            label.pack(pady=10)
            
            setattr(tab, "content_label", label)
    
    def cargar_archivo_txt(self):
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
                
                self.dominios_actuales = lineas
                
                total = len(lineas)
                contador = Counter(lineas)
                repetidos = {k: v for k, v in contador.items() if v > 1}
                unicos = len(contador)
                
                contenido_texto = "\n".join(lineas)
                self.tabs["contenido"].content_label.configure(
                    text=f"Total de entradas: {total}\n\nContenido:\n{contenido_texto}",
                    justify="left"
                )
                
                if repetidos:
                    repetidos_texto = "\n".join([f"{k} (repetido {v} veces)" for k, v in repetidos.items()])
                    self.tabs["repetidos"].content_label.configure(
                        text=f"Entradas repetidas ({len(repetidos)}):\n\n{repetidos_texto}",
                        justify="left"
                    )
                else:
                    self.tabs["repetidos"].content_label.configure(
                        text="No se encontraron entradas repetidas",
                        justify="left"
                    )
                
                stats_text = (
                    f"Total de entradas: {total}\n"
                    f"Entradas únicas: {unicos}\n"
                    f"Entradas repetidas: {len(repetidos)}\n"
                    f"Porcentaje de duplicados: {len(repetidos)/unicos*100:.2f}%"
                )
                self.tabs["estadisticas"].content_label.configure(
                    text=stats_text,
                    justify="left"
                )
                
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo leer el archivo: {str(e)}")
    
    def limpiar_resultados(self):
        for tab in self.tabs.values():
            tab.content_label.configure(text="No hay datos para mostrar")
        self.dominios_actuales = []
    
    def guardar_archivo_procesado(self):
        if not hasattr(self, 'dominios_actuales') or not self.dominios_actuales:
            messagebox.showwarning("Advertencia", "No hay datos para guardar")
            return
        
        dominios_procesados = set()
        
        for dominio in self.dominios_actuales:
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
                
                self.tabs["estadisticas"].content_label.configure(
                    text=f"Dominios únicos guardados: {len(dominios_procesados)}\n\n" +
                         "Ejemplos:\n" + '\n'.join(sorted(dominios_procesados)[:5]) + 
                         ("\n..." if len(dominios_procesados) > 5 else ""),
                    justify="left"
                )
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar: {str(e)}")
    
    def abrir_validacion(self):
        try:
            app = AppValidacion(self)
            app.mainloop()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo abrir la ventana de validación: {str(e)}")
    
    
    def cerrar_sesion(self):
        self.destroy()
        self.login_window.deiconify()
    
    def on_close(self):
        self.cerrar_sesion()

# ================== INTERFAZ DE VALIDACIÓN ==================
if __name__ == "__main__":
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("blue")
    app = AppLogin()
    app.mainloop()