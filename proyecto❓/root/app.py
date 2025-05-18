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
import whois


class AppRoot(customtkinter.CTk):
    def __init__(self, login_window, username):
        super().__init__()
        self.login_window = login_window
        self.username = username
        
        self.title(f"Interfaz Root - {username}")
        self.geometry("1200x800")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.setup_ui()
        self.mainloop()
    

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.frame_navegacion = customtkinter.CTkFrame(self, width=200, corner_radius=0)
        self.frame_navegacion.grid(row=0, column=0, sticky="nsew")
        self.frame_navegacion.grid_rowconfigure(6, weight=1)
        
        self.frame_contenido = customtkinter.CTkFrame(self, corner_radius=0)
        self.frame_contenido.grid(row=0, column=1, sticky="nsew")
        self.frame_contenido.grid_rowconfigure(0, weight=1)
        self.frame_contenido.grid_columnconfigure(0, weight=1)

        self.frame_superior = customtkinter.CTkFrame(self.frame_contenido, height=50)
        self.frame_superior.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Eliminar el botón de cerrar sesión
        # boton_cerrar_sesion = customtkinter.CTkButton(
        #     self.frame_superior,
        #     text="Cerrar sesión",
        #     command=self.cerrar_sesion,
        #     width=120,
        #     fg_color="#d9534f",
        #     hover_color="#c9302c"
        # )
        # boton_cerrar_sesion.pack(side="right", padx=20)
        
        # Botones de navegación
        botones_nav = [
            ("📊 Dashboard", self.mostrar_dashboard),
            ("🔍 SOC", self.mostrar_soc),  # Nuevo botón para el SOC
            ("✉️ Correo", self.mostrar_correo),
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
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(0, weight=0)  
        frame_principal.grid_rowconfigure(1, weight=1)  

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Dashboard Root - Resumen del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.grid(row=0, column=0, pady=10, sticky="n")

        frame_metricas = customtkinter.CTkFrame(frame_principal)
        frame_metricas.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        frame_metricas.grid_columnconfigure((0, 1, 2, 3), weight=1) 

   
        stats = self.obtener_estadisticas()

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
        
        datos = self.obtener_datos_graficos()
        
        fig1, ax1 = plt.subplots(figsize=(8, 4))
        datos['actividad_usuarios'].plot(kind='bar', ax=ax1, color='skyblue')
        ax1.set_title('Actividad por Usuario (últimos 30 días)')
        ax1.set_ylabel('Número de acciones')
        
        canvas1 = FigureCanvasTkAgg(fig1, master=frame_principal)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
        
        fig2, ax2 = plt.subplots(figsize=(8, 4))
        datos['tipos_reportes'].plot(kind='pie', autopct='%1.1f%%', ax=ax2)
        ax2.set_title('Distribución de Tipos de Reportes')
        ax2.set_ylabel('')
        
        canvas2 = FigureCanvasTkAgg(fig2, master=frame_principal)
        canvas2.draw()
        canvas2.get_tk_widget().pack(fill="both", expand=True, padx=20, pady=10)
    
    def mostrar_reportes(self):
        """Muestra el historial de reportes generados con opciones de filtro"""
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

        frame_filtros = customtkinter.CTkFrame(frame_principal)
        frame_filtros.pack(fill="x", padx=20, pady=10)

        label_fecha_inicio = customtkinter.CTkLabel(frame_filtros, text="Fecha inicio:")
        label_fecha_inicio.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        entrada_fecha_inicio = customtkinter.CTkEntry(frame_filtros, width=150)
        entrada_fecha_inicio.grid(row=0, column=1, padx=5, pady=5)

        label_fecha_fin = customtkinter.CTkLabel(frame_filtros, text="Fecha fin:")
        label_fecha_fin.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        entrada_fecha_fin = customtkinter.CTkEntry(frame_filtros, width=150)
        entrada_fecha_fin.grid(row=0, column=3, padx=5, pady=5)

        label_tipo = customtkinter.CTkLabel(frame_filtros, text="Tipo:")
        label_tipo.grid(row=0, column=4, padx=5, pady=5, sticky="w")
        combo_tipo = customtkinter.CTkComboBox(
            frame_filtros,
            values=["Todos", "safe", "malicious", "error"],
            width=150
        )
        combo_tipo.set("Todos")
        combo_tipo.grid(row=0, column=5, padx=5, pady=5)

        boton_aplicar = customtkinter.CTkButton(
            frame_filtros,
            text="Aplicar Filtros",
            command=lambda: self.actualizar_tabla_reportes(
                entrada_fecha_inicio.get(),
                entrada_fecha_fin.get(),
                combo_tipo.get()
            )
        )
        boton_aplicar.grid(row=0, column=6, padx=10, pady=5)
        self.frame_tabla_reportes = customtkinter.CTkScrollableFrame(frame_principal)
        self.frame_tabla_reportes.pack(fill="both", expand=True, padx=20, pady=10)

        self.actualizar_tabla_reportes()
    
    def mostrar_usuarios(self):
        """Muestra la gestión de usuarios del sistema con filtros"""
        self.limpiar_contenido()  

        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(1, weight=1)

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Gestión de Usuarios",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)

        frame_filtros = customtkinter.CTkFrame(frame_principal)
        frame_filtros.pack(fill="x", padx=20, pady=10)

        label_nombre = customtkinter.CTkLabel(frame_filtros, text="Nombre:")
        label_nombre.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        entrada_nombre = customtkinter.CTkEntry(frame_filtros, width=150)
        entrada_nombre.grid(row=0, column=1, padx=5, pady=5)

        label_rol = customtkinter.CTkLabel(frame_filtros, text="Rol:")
        label_rol.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        combo_rol = customtkinter.CTkComboBox(
            frame_filtros,
            values=["Todos", "root", "administrador", "usuario"],
            width=150
        )
        combo_rol.set("Todos")
        combo_rol.grid(row=0, column=3, padx=5, pady=5)

        boton_aplicar = customtkinter.CTkButton(
            frame_filtros,
            text="Aplicar Filtros",
            command=lambda: self.actualizar_tabla_usuarios(
                entrada_nombre.get(),
                combo_rol.get()
            )
        )
        boton_aplicar.grid(row=0, column=4, padx=10, pady=5)


        self.frame_tabla_usuarios = customtkinter.CTkScrollableFrame(frame_principal)
        self.frame_tabla_usuarios.pack(fill="both", expand=True, padx=20, pady=10)

        self.actualizar_tabla_usuarios()
    
    # ========== FUNCIONES DE DATOS ==========
    def obtener_estadisticas(self):
        """Obtiene estadísticas del sistema para el dashboard"""
        conn = sqlite3.connect('reportes.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM reportes")
        total_reportes = cursor.fetchone()[0]
        
        conn_usuarios = sqlite3.connect('usuarios.db')
        cursor_usuarios = conn_usuarios.cursor()
        cursor_usuarios.execute("SELECT COUNT(*) FROM usuarios")
        total_usuarios = cursor_usuarios.fetchone()[0]
        conn_usuarios.close()
        
        cursor.execute("""
            SELECT COUNT(*) FROM reportes 
            WHERE fecha >= datetime('now', '-7 days')
            AND resultado LIKE '%malicioso%' OR resultado LIKE '%sospechoso%'
        """)
        alertas_7dias = cursor.fetchone()[0]
        
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
        
        df_actividad = pd.read_sql("""
            SELECT usuario, COUNT(*) as acciones 
            FROM reportes 
            WHERE fecha >= datetime('now', '-30 days')
            GROUP BY usuario
            ORDER BY acciones DESC
            LIMIT 10
        """, conn)
        
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
        try:
            conn = sqlite3.connect('reportes.db')
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, fecha, dominio, resultado
                FROM reportes
                ORDER BY fecha DESC
                LIMIT ?
            ''', (limite,))
            
            reportes = cursor.fetchall()
            conn.close()
            return reportes
        except Exception as e:
            print(f"Error al obtener reportes: {e}")
            return []
    
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
            if password:  
                password_hash = sha256(password.encode()).hexdigest()
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, contraseña=?, rol=?
                    WHERE id=?
                """, (nombre, password_hash, rol, id_usuario))
            else:  
                cursor.execute("""
                    UPDATE usuarios 
                    SET nombre=?, rol=?
                    WHERE id=?
                """, (nombre, rol, id_usuario))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario actualizado correctamente")
            ventana.destroy()
            self.mostrar_usuarios() 
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
                self.mostrar_usuarios()  
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
            cursor.execute("SELECT id FROM usuarios WHERE nombre=?", (nombre,))
            if cursor.fetchone():
                messagebox.showerror("Error", "El nombre de usuario ya existe")
                return
            
            password_hash = sha256(password.encode()).hexdigest()
            
            cursor.execute("""
                INSERT INTO usuarios (nombre, contraseña, rol)
                VALUES (?, ?, ?)
            """, (nombre, password_hash, rol))
            
            conn.commit()
            messagebox.showinfo("Éxito", "Usuario creado correctamente")
            ventana.destroy()
            self.mostrar_usuarios() 
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo crear el usuario: {str(e)}")
        finally:
            conn.close()
    
    def mostrar_configuracion(self):
        """Muestra la configuración del sistema"""
        self.limpiar_contenido()

        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(1, weight=1)

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Configuración del Sistema",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)

        frame_agregar_correo = customtkinter.CTkFrame(frame_principal)
        frame_agregar_correo.pack(fill="x", padx=20, pady=10)

        label_agregar_correo = customtkinter.CTkLabel(
            frame_agregar_correo,
            text="Agregar correo manualmente:",
            font=("Arial", 14)
        )
        label_agregar_correo.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        entrada_correo = customtkinter.CTkEntry(frame_agregar_correo, width=300)
        entrada_correo.grid(row=0, column=1, padx=5, pady=5)

        boton_agregar_correo = customtkinter.CTkButton(
            frame_agregar_correo,
            text="Agregar",
            command=lambda: self.agregar_correo(entrada_correo.get())
        )
        boton_agregar_correo.grid(row=0, column=2, padx=5, pady=5)

        frame_importar_correos = customtkinter.CTkFrame(frame_principal)
        frame_importar_correos.pack(fill="x", padx=20, pady=10)

        label_importar_correos = customtkinter.CTkLabel(
            frame_importar_correos,
            text="Importar correos desde un archivo:",
            font=("Arial", 14)
        )
        label_importar_correos.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        boton_importar_correos = customtkinter.CTkButton(
            frame_importar_correos,
            text="Seleccionar archivo",
            command=self.importar_correos_desde_archivo
        )
        boton_importar_correos.grid(row=0, column=1, padx=5, pady=5)

        label_lista_correos = customtkinter.CTkLabel(
            frame_principal,
            text="Lista de Correos Registrados:",
            font=("Arial", 14, "bold")
        )
        label_lista_correos.pack(pady=(20, 10))

        frame_lista_correos = customtkinter.CTkScrollableFrame(frame_principal)
        frame_lista_correos.pack(fill="both", expand=True, padx=20, pady=10)

        try:
            conn = sqlite3.connect('correo.db')
            cursor = conn.cursor()
            cursor.execute("SELECT id, correo FROM correos")
            correos = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener correos: {e}")
            correos = []

        self.correos_seleccionados = {}

        for correo in correos:
            var = customtkinter.BooleanVar()
            self.correos_seleccionados[correo[0]] = var

            frame_correo = customtkinter.CTkFrame(frame_lista_correos, fg_color="transparent")
            frame_correo.pack(fill="x", padx=10, pady=5)

            checkbox = customtkinter.CTkCheckBox(
                frame_correo,
                text=correo[1],
                variable=var,
                font=("Arial", 12)
            )
            checkbox.pack(side="left", padx=10)

        boton_eliminar_seleccionados = customtkinter.CTkButton(
            frame_principal,
            text="Eliminar Seleccionados",
            command=self.eliminar_correos_seleccionados,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_eliminar_seleccionados.pack(pady=10)
    
    def cerrar_sesion(self):
        """Cierra la sesión y vuelve al login"""
        self.destroy()
        self.login_window.deiconify()
    
    def on_close(self):
        """Maneja el cierre de la ventana"""
        self.cerrar_sesion()

    def actualizar_tabla_reportes(self, fecha_inicio=None, fecha_fin=None, tipo="Todos"):
        """Actualiza la tabla de reportes según los filtros seleccionados"""
        for widget in self.frame_tabla_reportes.winfo_children():
            widget.destroy()

        encabezados = ["ID", "Fecha", "Dominio", "Resultado"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                self.frame_tabla_reportes,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados) - 1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")

        query = "SELECT id, fecha, dominio, resultado FROM reportes WHERE 1=1"
        params = []

        if fecha_inicio:
            query += " AND fecha >= ?"
            params.append(fecha_inicio)
        if fecha_fin:
            query += " AND fecha <= ?"
            params.append(fecha_fin)
        if tipo != "Todos":
            query += " AND resultado = ?"
            params.append(tipo)

        query += " ORDER BY fecha DESC"
        try:
            conn = sqlite3.connect('reportes.db')
            cursor = conn.cursor()
            cursor.execute(query, params)
            reportes = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener reportes: {e}")
            reportes = []

        for i, reporte in enumerate(reportes, start=1):
            for j, campo in enumerate(reporte):
                label = customtkinter.CTkLabel(
                    self.frame_tabla_reportes,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")

    def actualizar_tabla_usuarios(self, nombre=None, rol="Todos"):
        """Actualiza la tabla de usuarios según los filtros seleccionados"""
        for widget in self.frame_tabla_usuarios.winfo_children():
            widget.destroy()

        encabezados = ["ID", "Nombre", "Rol", "Acciones"]
        for i, encabezado in enumerate(encabezados):
            label = customtkinter.CTkLabel(
                self.frame_tabla_usuarios,
                text=encabezado,
                font=("Arial", 12, "bold"),
                width=120 if i < len(encabezados) - 1 else 200
            )
            label.grid(row=0, column=i, padx=5, pady=5, sticky="w")

        query = "SELECT id, nombre, rol FROM usuarios WHERE 1=1"
        params = []

        if nombre:
            query += " AND nombre LIKE ?"
            params.append(f"%{nombre}%")
        if rol != "Todos":
            query += " AND rol = ?"
            params.append(rol)

        query += " ORDER BY nombre"

        try:
            conn = sqlite3.connect('usuarios.db')
            cursor = conn.cursor()
            cursor.execute(query, params)
            usuarios = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener usuarios: {e}")
            usuarios = []

        for i, usuario in enumerate(usuarios, start=1):
            for j, campo in enumerate(usuario):
                label = customtkinter.CTkLabel(
                    self.frame_tabla_usuarios,
                    text=str(campo),
                    font=("Arial", 12),
                    width=120
                )
                label.grid(row=i, column=j, padx=5, pady=5, sticky="w")

            frame_botones = customtkinter.CTkFrame(self.frame_tabla_usuarios, fg_color="transparent")
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

    def mostrar_correo(self):
        """Muestra el apartado para enviar correos"""
        self.limpiar_contenido()  

        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(1, weight=1)

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="Enviar Correo",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)

        label_mensaje = customtkinter.CTkLabel(frame_principal, text="Mensaje:")
        label_mensaje.pack(pady=(10, 0))
        entrada_mensaje = customtkinter.CTkTextbox(frame_principal, height=200, wrap="word")
        entrada_mensaje.pack(fill="x", padx=20, pady=10)

        boton_enviar = customtkinter.CTkButton(
            frame_principal,
            text="Enviar Correo",
            command=lambda: self.enviar_correo(entrada_mensaje.get("1.0", "end").strip()),
            fg_color="#4CAF50",
            hover_color="#45a049"
        )
        boton_enviar.pack(pady=10)

        label_lista_correos = customtkinter.CTkLabel(
            frame_principal,
            text="Lista de Correos Registrados:",
            font=("Arial", 14, "bold")
        )
        label_lista_correos.pack(pady=(20, 10))

        frame_lista_correos = customtkinter.CTkScrollableFrame(frame_principal)
        frame_lista_correos.pack(fill="both", expand=True, padx=20, pady=10)
        try:
            conn = sqlite3.connect('correo.db')
            cursor = conn.cursor()
            cursor.execute("SELECT correo FROM correos")
            correos = cursor.fetchall()
            conn.close()
        except Exception as e:
            print(f"Error al obtener correos: {e}")
            correos = []

        for correo in correos:
            label_correo = customtkinter.CTkLabel(
                frame_lista_correos,
                text=correo[0],
                font=("Arial", 12)
            )
            label_correo.pack(anchor="w", padx=10, pady=5)

    def enviar_correo(self, mensaje):
        """Envía el mensaje a todos los correos registrados"""
        if not mensaje:
            messagebox.showwarning("Advertencia", "El mensaje no puede estar vacío.")
            return

        try:
            conn = sqlite3.connect('correo.db')
            cursor = conn.cursor()
            cursor.execute("SELECT correo FROM correos")
            correos = [correo[0] for correo in cursor.fetchall()]
            conn.close()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo obtener la lista de correos: {e}")
            return

        if not correos:
            messagebox.showwarning("Advertencia", "No hay correos registrados para enviar el mensaje.")
            return

        for correo in correos:
            print(f"Enviando mensaje a: {correo}")

        messagebox.showinfo("Éxito", "El mensaje se ha enviado a todos los correos registrados.")

    def agregar_correo(self, correo):
        """Agrega un correo a la base de datos"""
        if not correo:
            messagebox.showwarning("Advertencia", "El campo de correo no puede estar vacío.")
            return

        try:
            conn = sqlite3.connect('correo.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO correos (correo) VALUES (?)", (correo,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Éxito", f"El correo '{correo}' se ha agregado correctamente.")
            self.mostrar_configuracion()  
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo agregar el correo: {e}")

    def importar_correos_desde_archivo(self):
        """Importa correos desde un archivo seleccionado"""
        archivo = filedialog.askopenfilename(
            title="Seleccionar archivo",
            filetypes=[("Archivos de texto", "*.txt")]
        )

        if not archivo:
            return

        try:
            with open(archivo, "r") as f:
                correos = [line.strip() for line in f if line.strip()]

            if not correos:
                messagebox.showwarning("Advertencia", "El archivo está vacío o no contiene correos válidos.")
                return

            conn = sqlite3.connect('correo.db')
            cursor = conn.cursor()
            cursor.executemany("INSERT INTO correos (correo) VALUES (?)", [(correo,) for correo in correos])
            conn.commit()
            conn.close()

            messagebox.showinfo("Éxito", f"Se han importado {len(correos)} correos correctamente.")
            self.mostrar_configuracion()  
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo importar los correos: {e}")

    def editar_correo(self, correo):
        """Abre una ventana para editar un correo"""
        ventana = customtkinter.CTkToplevel(self)
        ventana.title("Editar Correo")
        ventana.geometry("400x200")

        frame_principal = customtkinter.CTkFrame(ventana)
        frame_principal.pack(fill="both", expand=True, padx=10, pady=10)

        label_correo = customtkinter.CTkLabel(frame_principal, text="Correo:")
        label_correo.pack(pady=(10, 0))

        entrada_correo = customtkinter.CTkEntry(frame_principal, width=300)
        entrada_correo.insert(0, correo[1])
        entrada_correo.pack(pady=5)

        
        def guardar_cambios():
            nuevo_correo = entrada_correo.get().strip()
            if not nuevo_correo:
                messagebox.showwarning("Advertencia", "El campo de correo no puede estar vacío.")
                return

            try:
                conn = sqlite3.connect('correo.db')
                cursor = conn.cursor()
                cursor.execute("UPDATE correos SET correo = ? WHERE id = ?", (nuevo_correo, correo[0]))
                conn.commit()
                conn.close()
                messagebox.showinfo("Éxito", "Correo actualizado correctamente.")
                ventana.destroy()
                self.mostrar_configuracion()  
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo actualizar el correo: {e}")

        boton_guardar = customtkinter.CTkButton(
            frame_principal,
            text="Guardar",
            command=guardar_cambios
        )
        boton_guardar.pack(pady=10)

        boton_cancelar = customtkinter.CTkButton(
            frame_principal,
            text="Cancelar",
            command=ventana.destroy,
            fg_color="#d9534f",
            hover_color="#c9302c"
        )
        boton_cancelar.pack(pady=10)

    def eliminar_correo(self, correo):
        """Elimina un correo de la base de datos"""
        confirmacion = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Estás seguro de eliminar el correo '{correo[1]}'? Esta acción no se puede deshacer."
        )
        if confirmacion:
            try:
                conn = sqlite3.connect('correo.db')
                cursor = conn.cursor()
                cursor.execute("DELETE FROM correos WHERE id = ?", (correo[0],))
                conn.commit()
                conn.close()
                messagebox.showinfo("Éxito", "Correo eliminado correctamente.")
                self.mostrar_configuracion() 
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar el correo: {e}")

    def eliminar_correos_seleccionados(self):
        """Elimina los correos seleccionados de la base de datos"""

        correos_a_eliminar = [id_correo for id_correo, var in self.correos_seleccionados.items() if var.get()]

        if not correos_a_eliminar:
            messagebox.showwarning("Advertencia", "No se ha seleccionado ningún correo para eliminar.")
            return

        confirmacion = messagebox.askyesno(
            "Confirmar eliminación",
            f"¿Estás seguro de eliminar {len(correos_a_eliminar)} correos seleccionados? Esta acción no se puede deshacer."
        )
        if confirmacion:
            try:
                conn = sqlite3.connect('correo.db')
                cursor = conn.cursor()
                cursor.executemany("DELETE FROM correos WHERE id = ?", [(id_correo,) for id_correo in correos_a_eliminar])
                conn.commit()
                conn.close()
                messagebox.showinfo("Éxito", "Correos eliminados correctamente.")
                self.mostrar_configuracion()  
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo eliminar los correos: {e}")

    def consultar_virustotal(self, entrada):
        """Consulta VirusTotal para obtener información sobre un dominio o IP"""
        API_KEY = "66d00a63db6ec9baebea11609c9d6d9b94e78cadd185a326397375c0e661bd81"
        url = f"https://www.virustotal.com/api/v3/domains/{entrada}" if "." in entrada else f"https://www.virustotal.com/api/v3/ip_addresses/{entrada}"
        headers = {"x-apikey": API_KEY}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return json.dumps(data, indent=2)
            elif response.status_code == 403:
                return "Acceso denegado: Verifique su clave de API."
            elif response.status_code == 429:
                return "Límite de solicitudes alcanzado: Intente más tarde."
            else:
                return f"Error desconocido (Código {response.status_code})."
        except requests.exceptions.RequestException as e:
            return f"Error al consultar VirusTotal: {e}"

    def consultar_abuseipdb(self, entrada):
        """Consulta AbuseIPDB para obtener información sobre una dirección IP"""
        API_KEY = "74036361621bee245b8e292491a1e334653952c49b868d89bd472197c91abac535c7a0b612d1d3eb"
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": entrada,
            "maxAgeInDays": 90
        }

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return json.dumps(data, indent=2)
            elif response.status_code == 403:
                return "Acceso denegado: Verifique su clave de API."
            elif response.status_code == 429:
                return "Límite de solicitudes alcanzado: Intente más tarde."
            else:
                return f"Error desconocido (Código {response.status_code})."
        except requests.exceptions.RequestException as e:
            return f"Error al consultar AbuseIPDB: {e}"

    def consultar_whois(self, entrada):
        """Consulta información de Whois para un dominio"""
        try:
            w = whois.whois(entrada)
            return json.dumps(w, indent=2, default=str)  
        except Exception as e:
            return f"Error al consultar Whois: {e}"

    def mostrar_soc(self):
        """Muestra el SOC para analizar dominios o direcciones IP"""
        self.limpiar_contenido()  

        
        frame_principal = customtkinter.CTkFrame(self.frame_contenido)
        frame_principal.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_principal.grid_columnconfigure(0, weight=1)
        frame_principal.grid_rowconfigure(1, weight=1)

        label_titulo = customtkinter.CTkLabel(
            frame_principal,
            text="SOC - Análisis de Dominios/IP",
            font=("Arial", 18, "bold")
        )
        label_titulo.pack(pady=20)


        label_entrada = customtkinter.CTkLabel(frame_principal, text="Dominio o Dirección IP:")
        label_entrada.pack(pady=(10, 0))
        entrada_dominio_ip = customtkinter.CTkEntry(frame_principal, width=400)
        entrada_dominio_ip.pack(pady=5)

        entrada_dominio_ip.bind("<Return>", lambda event: self.analizar_dominio_ip(entrada_dominio_ip.get().strip()))

        frame_botones = customtkinter.CTkFrame(frame_principal)
        frame_botones.pack(pady=10)

        boton_whois_web = customtkinter.CTkButton(
            frame_botones,
            text="Abrir Whois Web",
            command=lambda: abrir_whois_web(entrada_dominio_ip.get().strip()),
            width=200
        )
        boton_whois_web.pack(side="left", padx=10)

        boton_virustotal_graph = customtkinter.CTkButton(
            frame_botones,
            text="Abrir VirusTotal Graph",
            command=lambda: self.abrir_virustotal_graph(entrada_dominio_ip.get().strip()),
            width=200,
            fg_color="#4CAF50",
            hover_color="#45a049"
        )
        boton_virustotal_graph.pack(side="left", padx=10)

        self.frame_resultados_soc = customtkinter.CTkScrollableFrame(frame_principal)
        self.frame_resultados_soc.pack(fill="both", expand=True, padx=20, pady=10)

    def analizar_dominio_ip(self, entrada):
        """Analiza un dominio o dirección IP usando diferentes APIs"""
        if not entrada:
            messagebox.showwarning("Advertencia", "El campo no puede estar vacío.")
            return

        for widget in self.frame_resultados_soc.winfo_children():
            widget.destroy()


        label_progreso = customtkinter.CTkLabel(
            self.frame_resultados_soc,
            text="Analizando, por favor espere...",
            font=("Arial", 14)
        )
        label_progreso.pack(pady=10)

        self.update()


        resultados = []

     
        abuseip_resultado = self.consultar_abuseipdb(entrada)
        resultados.append(("AbuseIPDB", abuseip_resultado))

        
        whois_resultado = self.consultar_whois(entrada)
        resultados.append(("Whois", whois_resultado))

        
        for fuente, resultado in resultados:
            frame_resultado = customtkinter.CTkFrame(self.frame_resultados_soc)
            frame_resultado.pack(fill="x", padx=10, pady=10)  

            label_fuente = customtkinter.CTkLabel(
                frame_resultado,
                text=f"Resultados de {fuente}:",
                font=("Arial", 14, "bold")
            )
            label_fuente.pack(pady=(10, 0))

            texto_resultado = customtkinter.CTkTextbox(
                frame_resultado,
                wrap="word",
                height=150
            )
            texto_resultado.insert("1.0", resultado)
            texto_resultado.configure(state="disabled")
            texto_resultado.pack(fill="x", padx=10, pady=5)

    def abrir_virustotal_graph(self, entrada):
        """Abre el gráfico de VirusTotal en el navegador"""
        if not entrada:
            messagebox.showwarning("Advertencia", "El campo no puede estar vacío.")
            return

        url = f"https://www.virustotal.com/graph/{entrada}"
        webbrowser.open(url)

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

def inicializar_base_correos():
    """Crea la base de datos y la tabla 'correos' si no existe"""
    try:
        conexion = sqlite3.connect('correo.db')
        cursor = conexion.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS correos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            correo TEXT NOT NULL
        )
        ''')
        
        conexion.commit()
        print("Base de datos 'correo.db' inicializada correctamente.")
    except Exception as e:
        print(f"Error al inicializar la base de datos 'correo.db': {e}")
    finally:
        conexion.close()


def abrir_whois_web(dominio):
    """Abre un servicio web de Whois en el navegador"""
    url = f"https://whois.domaintools.com/{dominio}"
    webbrowser.open(url)