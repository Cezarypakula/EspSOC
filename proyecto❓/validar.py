import customtkinter
from tkinter import filedialog, messagebox
import webbrowser
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import plotly.express as px
import tempfile
import os
import discord
from discord.ext import commands
import asyncio
import threading
import time
import sqlite3

DISCORD_BOT_TOKEN = "XXXXXXXXXXXXXXX"  # token dc
USER_ID = "XXXXXXXXXX"  # ID del usuario de Discord

def inicializar_base_reportes():
    """Crea la base de datos y la tabla 'reportes' si no existe"""
    try:
        conexion = sqlite3.connect('reportes.db')
        cursor = conexion.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS reportes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            dominio TEXT NOT NULL,
            resultado TEXT NOT NULL
        )
        ''')
        
        conexion.commit()
        print("Base de datos y tabla 'reportes' creadas correctamente.")
    except Exception as e:
        print(f"Error al crear la base de datos: {e}")
    finally:
        conexion.close()

def guardar_reporte(dominio, resultado):
    """Guarda un reporte en la base de datos"""
    try:
        conexion = sqlite3.connect('reportes.db')
        cursor = conexion.cursor()
        
        cursor.execute('''
        INSERT INTO reportes (dominio, resultado)
        VALUES (?, ?)
        ''', (dominio, resultado))
        
        conexion.commit()
        print(f"Reporte guardado: Dominio={dominio}, Resultado={resultado}")
    except Exception as e:
        print(f"Error al guardar el reporte: {e}")
    finally:
        conexion.close()

class DiscordBot:
    def __init__(self):
        self.bot = commands.Bot(command_prefix='!', intents=discord.Intents.all())
        self.token = DISCORD_BOT_TOKEN
        self.user_id = USER_ID
        self.is_ready = False
        self.loop = asyncio.new_event_loop()
        
        self.bot.event(self.on_ready)
        
    async def on_ready(self):
        print(f'Bot conectado como {self.bot.user}')
        self.is_ready = True
        
    async def send_dm(self, content):
        if not self.is_ready:
            return False
            
        try:
            user = await self.bot.fetch_user(self.user_id)
            if user:
                await user.send(content)
                return True
            return False
        except Exception as e:
            print(f"Error sending DM: {e}")
            return False

    def start_bot(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.bot.start(self.token))
        except discord.LoginFailure:
            print("Error: Token inválido")
        except Exception as e:
            print(f"Error starting bot: {e}")
        finally:
            if not self.loop.is_closed():
                self.loop.close()

def leer_dominios(archivo):
    try:
        with open(archivo, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []

def verificar_dominio(dominio):
    API_KEY = "XXXXXXXXXXXXXXXX"  # Reemplaza con tu clave de API de VirusTotal
    url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            if stats["malicious"] > 0 or stats["suspicious"] > 0:
                return f"[⚠️] {dominio} - Malicioso: {stats['malicious']}, Sospechoso: {stats['suspicious']}\n", "malicious"
            else:
                return f"[✅] {dominio} es seguro\n", "safe"
        elif response.status_code == 403:
            return f"[❌] Acceso denegado: Verifique su clave de API\n", "error"
        elif response.status_code == 429:
            return f"[❌] Límite de solicitudes alcanzado: Intente más tarde\n", "error"
        else:
            return f"[❌] Error desconocido (Código {response.status_code})\n", "error"
    except requests.exceptions.RequestException as e:
        return f"[❌] Error con {dominio}: {e}\n", "error"

class AppValidacion(customtkinter.CTk):
    def __init__(self, admin_window=None):
        super().__init__()
        self.admin_window = admin_window
        if (admin_window):
            admin_window.withdraw()
        
        self.title("Validación de Dominios/IP")
        self.geometry("1000x700")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        ########Discord###########
        self.discord_bot = DiscordBot()
        self.bot_thread = threading.Thread(target=self.discord_bot.start_bot, daemon=True)
        self.bot_thread.start()
        
        self.after(3000, self.check_bot_connection)
        
        self.setup_ui()
        self.grafico_path = ""
    
    def check_bot_connection(self):
        if not self.discord_bot.is_ready:
            messagebox.showwarning("Advertencia", 
                "El bot de Discord no se ha conectado. Verifique:\n"
                "1. Que el token sea correcto\n"
                "2. Que el bot tenga los permisos necesarios\n"
                "3. Que no haya problemas de conexión a Internet")
    
    def setup_ui(self):
        self.frame_controles = customtkinter.CTkFrame(self, width=220)
        self.frame_controles.pack(side="left", fill="y", padx=10, pady=10)
        
        self.frame_principal = customtkinter.CTkFrame(self)
        self.frame_principal.pack(side="right", expand=True, fill="both", padx=10, pady=10)
        
        self.info_frame = customtkinter.CTkFrame(self.frame_controles)
        self.info_frame.pack(pady=10, fill="x")
        
        self.info_label = customtkinter.CTkLabel(self.info_frame, text="Información de análisis", font=("Arial", 14))
        self.info_label.pack(pady=5)
        
        self.info_stats_label = customtkinter.CTkLabel(
            self.info_frame, 
            text="Dominios: 0\nSeguros: 0\nMaliciosos: 0\nErrores: 0",
            font=("Arial", 12),
            wraplength=180
        )
        self.info_stats_label.pack(pady=5)
        
        self.control_frame = customtkinter.CTkFrame(self.frame_controles)
        self.control_frame.pack(pady=10, fill="x")
        
        self.btn_importar = customtkinter.CTkButton(
            self.control_frame,
            text="Importar archivo",
            command=self.importar_archivo,
            width=200
        )
        self.btn_importar.pack(pady=5)
        
        self.btn_guardar = customtkinter.CTkButton(
            self.control_frame,
            text="Guardar resultados",
            command=self.guardar_resultados,
            width=200
        )
        self.btn_guardar.pack(pady=5)
        
        self.btn_grafico = customtkinter.CTkButton(
            self.control_frame,
            text="Mostrar gráfico",
            command=self.mostrar_grafico_interactivo,
            width=200,
            fg_color="#6a0dad",
            hover_color="#4b0082"
        )
        self.btn_grafico.pack(pady=5)
        
        self.btn_discord = customtkinter.CTkButton(
            self.control_frame,
            text="Enviar a Discord",
            command=self.mostrar_dialogo_discord,
            width=200,
            fg_color="#7289DA",
            hover_color="#5a6eab"
        )
        self.btn_discord.pack(pady=5)
        
        self.btn_firewall = customtkinter.CTkButton(
            self.control_frame,
            text="Agregar al firewall",
            command=self.agregar_al_firewall,
            width=200
        )
        self.btn_firewall.pack(pady=5)
        
        self.resultados_frame = customtkinter.CTkFrame(self.frame_principal)
        self.resultados_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        self.resultados_textbox = customtkinter.CTkTextbox(
            self.resultados_frame,
            wrap="word",
            font=("Consolas", 12)
        )
        self.resultados_textbox.pack(expand=True, fill="both")
        
        self.frame_graficos = customtkinter.CTkFrame(self.frame_principal, height=200)
        self.frame_graficos.pack(fill="x", padx=10, pady=5)
        
        self.resultados_textbox.tag_config("safe", foreground="green")
        self.resultados_textbox.tag_config("malicious", foreground="red")
        self.resultados_textbox.tag_config("error", foreground="orange")
        self.resultados_textbox.tag_config("info", foreground="blue")
        
        self.btn_volver = customtkinter.CTkButton(
            self.frame_controles,
            text="Volver",
            command=self.on_close,
            width=200
        )
        self.btn_volver.pack(pady=20)
        
        self.resultados_textbox.insert("end", "Instrucciones:\n", "info")
        self.resultados_textbox.insert("end", "1. Importe un archivo TXT con dominios/IPs\n")
        self.resultados_textbox.insert("end", "2. Los resultados mostrarán análisis de VirusTotal y Spamhaus\n")
        self.resultados_textbox.insert("end", "3. Use los botones para guardar o enviar a Discord\n\n", "info")
    
    def importar_archivo(self):
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo", 
            filetypes=[("Archivos de texto", "*.txt")]
        )
        
        if archivo:
            self.resultados_textbox.delete("1.0", "end")
            self.resultados_textbox.insert("end", f"[🔍] Analizando archivo: {archivo}\n\n", "info")
            
            dominios = leer_dominios(archivo)
            if not dominios:
                self.resultados_textbox.insert("end", "[❌] El archivo está vacío o no contiene dominios válidos.\n", "error")
                return  # Salir si no hay dominios

            seguros = 0
            maliciosos = 0
            errores = 0

            def update_ui(resultado, tipo):
                nonlocal seguros, maliciosos, errores
                
                if tipo == "safe":
                    seguros += 1
                    tag = "safe"
                elif tipo == "malicious":
                    maliciosos += 1
                    tag = "malicious"
                else:
                    errores += 1
                    tag = "error"
                
                self.resultados_textbox.insert("end", resultado, tag)
                self.resultados_textbox.see("end")
                self.info_stats_label.configure(
                    text=f"Dominios: {len(dominios)}\nSeguros: {seguros}\nMaliciosos: {maliciosos}\nErrores: {errores}"
                )
                self.mostrar_grafico_basico(seguros, maliciosos, errores)
                self.update()

            def analizar_dominio(dominio):
                resultado, tipo = verificar_dominio(dominio)
                guardar_reporte(dominio, tipo)  
                return resultado, tipo

            def ejecutar_analisis():
                with ThreadPoolExecutor(max_workers=10) as executor:  
                    futures = {executor.submit(analizar_dominio, dominio): dominio for dominio in dominios}
                    for future in futures:
                        try:
                            resultado, tipo = future.result()
                            self.after(0, update_ui, resultado, tipo)
                        except Exception as e:
                            self.after(0, update_ui, f"[❌] Error al analizar {futures[future]}: {str(e)}\n", "error")

            threading.Thread(target=ejecutar_analisis, daemon=True).start()
    
    def mostrar_grafico_basico(self, seguros, maliciosos, errores):
        for widget in self.frame_graficos.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(6, 3))
        ax.bar(["Seguros", "Maliciosos", "Errores"], [seguros, maliciosos, errores], 
               color=["green", "red", "orange"])
        ax.set_title("Resumen de Análisis")

        self.grafico_path = os.path.join(tempfile.gettempdir(), "grafico_resumen.png")
        fig.savefig(self.grafico_path)
        plt.close(fig)

        canvas = FigureCanvasTkAgg(fig, master=self.frame_graficos)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
    
    def mostrar_grafico_interactivo(self):
        contenido = self.resultados_textbox.get("1.0", "end")
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
        
        temp_file = os.path.join(tempfile.gettempdir(), "grafico_dominios.html")
        fig.write_html(temp_file)
        webbrowser.open(f"file://{temp_file}")
    
    def guardar_resultados(self):
        resultados = self.resultados_textbox.get("1.0", "end").strip()
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
                
                self.resultados_textbox.insert("end", f"\n[✅] Resultados guardados en {archivo}\n", "info")
            except Exception as e:
                self.resultados_textbox.insert("end", f"\n[❌] Error al guardar: {str(e)}\n", "error")

    def mostrar_dialogo_discord(self):
        if not self.discord_bot.is_ready:
            messagebox.showerror("Error", "El bot de Discord no está conectado")
            return

        dialogo = customtkinter.CTkToplevel(self)
        dialogo.title("Enviar a Discord")
        dialogo.geometry("400x300")

        status = "✅ Conectado" if self.discord_bot.is_ready else "❌ Desconectado"
        status_label = customtkinter.CTkLabel(dialogo, text=f"Estado del bot: {status}")
        status_label.pack(pady=10)

        customtkinter.CTkLabel(dialogo, text="Mensaje adicional:").pack(pady=5)
        entry_mensaje = customtkinter.CTkEntry(dialogo, width=350)
        entry_mensaje.pack(pady=5)

        def enviar_mensaje():
            mensaje = entry_mensaje.get()
            contenido = self.resultados_textbox.get("1.0", "end").strip()

            discord_msg = f"**Resultados de Análisis**\n{mensaje}\n\n" if mensaje else "**Resultados de Análisis**\n"
            discord_msg += contenido[:1800]  

            try:
                async def send_with_attachment():
                    user = await self.discord_bot.bot.fetch_user(self.discord_bot.user_id)
                    with open(self.grafico_path, "rb") as file:
                        await user.send(content=discord_msg, file=discord.File(file, "grafico.png"))

                future = asyncio.run_coroutine_threadsafe(
                    send_with_attachment(),
                    self.discord_bot.loop
                )

                try:
                    future.result(timeout=10)
                    messagebox.showinfo("Éxito", "Mensaje enviado con gráfico")
                except asyncio.TimeoutError:
                    messagebox.showerror("Error", "Tiempo de espera agotado")
            except Exception as e:
                messagebox.showerror("Error", f"Error al enviar: {str(e)}")

        btn_enviar = customtkinter.CTkButton(
            dialogo,
            text="Enviar Mensaje",
            command=enviar_mensaje,
            fg_color="#7289DA",
            hover_color="#5a6eab"
        )
        btn_enviar.pack(pady=20)

        btn_reconectar = customtkinter.CTkButton(
            dialogo,
            text="Reintentar Conexión",
            command=self.reconnect_bot,
            fg_color="#4CAF50"
        )
        btn_reconectar.pack(pady=10)

        btn_cerrar = customtkinter.CTkButton(
            dialogo,
            text="Cerrar",
            command=dialogo.destroy,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        btn_cerrar.pack(pady=10)
    
    def reconnect_bot(self):
        if hasattr(self.discord_bot, 'bot') and self.discord_bot.is_ready:
            asyncio.run_coroutine_threadsafe(
                self.discord_bot.bot.close(),
                self.discord_bot.loop
            )
        
        self.discord_bot = DiscordBot()
        self.bot_thread = threading.Thread(target=self.discord_bot.start_bot, daemon=True)
        self.bot_thread.start()
        
        messagebox.showinfo("Info", "Intentando reconectar el bot...")
        self.after(3000, self.check_bot_connection)
    
    def agregar_al_firewall(self):
        contenido = self.resultados_textbox.get("1.0", "end")
        lineas_maliciosas = [line for line in contenido.split("\n") if "[⚠️]" in line]
        
        if lineas_maliciosas:
            dominios_maliciosos = [line.split(" - ")[0].replace("[⚠️] ", "") for line in lineas_maliciosas]
            self.resultados_textbox.insert("end", "\nDominios para bloquear:\n", "info")
            for dominio in dominios_maliciosos:
                self.resultados_textbox.insert("end", f"- {dominio}\n")
        else:
            self.resultados_textbox.insert("end", "\nNo se encontraron dominios maliciosos para bloquear\n", "info")
    
    def mostrar_reportes(self):
        """Muestra el historial de reportes generados"""
        self.limpiar_contenido()  

        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(0, weight=1)

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Historial de Reportes",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)

        try:
            conn = sqlite3.connect('reportes.db')
            cursor = conn.cursor()
            cursor.execute("SELECT id, fecha, dominio, resultado FROM reportes ORDER BY fecha DESC")
            reportes = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener reportes: {e}")
            reportes = []

        frame_tabla = customtkinter.CTkScrollableFrame(frame_principal)
        frame_tabla.pack(fill="both", expand=True, padx=20, pady=10)

        encabezados = ["ID", "Fecha", "Dominio", "Resultado"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                frame_tabla,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados) - 1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")

        for i, reporte in enumerate(reportes, start=1):
            for j, campo in enumerate(reporte):
                label = customtkinter.CTkLabel(
                    frame_tabla,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")
    
    def on_close(self):
        if hasattr(self, 'discord_bot') and self.discord_bot.is_ready:
            asyncio.run_coroutine_threadsafe(
                self.discord_bot.bot.close(),
                self.discord_bot.loop
            )
        
        if self.admin_window:
            self.admin_window.deiconify()
        self.destroy()

customtkinter.set_appearance_mode("dark")
customtkinter.set_default_color_theme("blue")

if __name__ == "__main__":
    inicializar_base_reportes()
    