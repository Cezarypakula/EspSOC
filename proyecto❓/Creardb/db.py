import sqlite3

conn = sqlite3.connect('usuarios.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    contraseña TEXT NOT NULL,
    rol TEXT NOT NULL
)
''')

cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES ('admin', '1234', 'root')")
cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES ('physco', '4g#3nd4/pys0', 'administrador')")
cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES ('usuario', '5678', 'usuario')")
cursor.execute("INSERT INTO usuarios (nombre, contraseña, rol) VALUES ('visitante', '0000', 'visitante')")

conn.commit()
conn.close()