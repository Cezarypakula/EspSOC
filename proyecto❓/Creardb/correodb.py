import sqlite3
import os 

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

inicializar_base_correos()

