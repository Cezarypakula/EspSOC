import sqlite3

def inicializar_base_reportes():
    """Crea la base de datos y la tabla 'reportes' si no existe"""
    try:
        conexion = sqlite3.connect('reportes.db')
        cursor = conexion.cursor()
        
        cursor.execute('DROP TABLE IF EXISTS reportes')
        
        cursor.execute('''
        CREATE TABLE reportes (
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

if __name__ == "__main__":
    inicializar_base_reportes()