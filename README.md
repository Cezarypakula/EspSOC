# 🛡️ SOC - Security Operations Center en Python

Bienvenido al repositorio de un poderoso y completo **SOC (Centro de Operaciones de Seguridad)** creado con Python. Esta plataforma permite analizar dominios/IPs en tiempo real usando VirusTotal, gestionar usuarios, generar reportes interactivos y notificar resultados a Discord.

---

## 🚀 Características Principales

🔐 **Sistema de Autenticación**
- Roles definidos: `root`, `administrador`, `usuario`
- Contraseñas cifradas con SHA-256
- Paneles personalizados por rol

🧠 **Análisis Inteligente de Dominios/IPs**
- Uso de la API de [VirusTotal](https://www.virustotal.com/)
- Verificación en listas negras de [Spamhaus](https://www.spamhaus.org/)
- Clasificación automática: `Seguro`, `Malicioso`, `Error`

📊 **Dashboard Interactivo**
- Métricas clave (reportes, usuarios, alertas)
- Visualización de actividad por usuario
- Gráficos de torta y barras (matplotlib y plotly)

📁 **Carga Inteligente de Archivos**
- Análisis masivo de `.txt` con dominios o IPs
- Detección y visualización de duplicados
- Limpieza automática y exportación a `.txt`, `.csv` o `.json`

📤 **Integración con Discord**
- Envío de resultados directamente al usuario por mensaje privado
- Bot funcional con conexión automática
- Envío de gráficos como imágenes adjuntas

👥 **Gestión de Usuarios**
- Crear, editar y eliminar usuarios
- Filtros dinámicos por nombre y rol
- Interfaz intuitiva con `customtkinter`

---

## 🛠️ Instalación

1. **Clona el repositorio**:
```bash
git clone https://github.com/tuusuario/soc-python.git
cd soc-python
```

2. **Instala las dependencias**:
```bash
pip install -r requirements.txt
```

3. **Ejecuta el proyecto**:
```bash
python pyqt.py
```

> 🧪 Usuario por defecto: `admin`  
> 🔑 Contraseña por defecto: `admin123`

---

## 📂 Estructura del Proyecto

```
📦 soc-python/
├── root/
│   └── app.py           # Interfaz avanzada para usuarios root (SOC, dashboard, reportes, usuarios)
├── pyqt.py              # Sistema de login, interfaz de administrador y acceso a funcionalidades
├── validar.py           # Módulo para análisis de dominios/IPs y envío a Discord
├── usuarios.db          # Base de datos SQLite para usuarios
├── reportes.db          # Base de datos SQLite para reportes de análisis
├── correo.db            # (Opcional) Correos guardados para envío masivo
├── requirements.txt     # Archivo con las dependencias del proyecto
└── README.md            # Documentación del proyecto
```

---

## 📈 Capturas de Pantalla

> *![image](https://github.com/user-attachments/assets/2f8b0f8c-9eaf-44a3-8e17-4d5aac0b01fe)*
> *![image](https://github.com/user-attachments/assets/34131284-ae73-492c-b2bd-33bbb18113bd)*
> *![image](https://github.com/user-attachments/assets/f8e85e80-0a03-4443-b425-0a2cd0b9d885)*
> *![image](https://github.com/user-attachments/assets/37504661-d62d-401d-bc73-10170598a068)*
> *![image](https://github.com/user-attachments/assets/a9bba4de-4328-4566-9a39-a606c35170d6)*
> *![image](https://github.com/user-attachments/assets/cd6d7dd0-4031-4fd0-b985-31f3b7b6adaa)*
> *![image](https://github.com/user-attachments/assets/f2b42674-ec41-446e-9c30-1a29ba219bf0)*
> *![image](https://github.com/user-attachments/assets/61455366-f2d8-4796-9f08-6d2a2f82ea43)*
> *![image](https://github.com/user-attachments/assets/ee586224-8de7-4165-9ba0-faa9b5bf58c5)*
> *![image](https://github.com/user-attachments/assets/c929b24b-8a5a-47c9-b0f3-a7ed6971277f)*
> *![image](https://github.com/user-attachments/assets/b158e29e-8c31-4ed5-91a1-c6aa87aed7e7)*
> *![image](https://github.com/user-attachments/assets/e5291e63-e601-497b-afc4-4aab181dd5c7)*
---

## 🎯 To-Do

- [ ] Dashboard web en Flask
- [ ] Integración con SIEMs (Splunk, Graylog, etc.)
- [ ] Sistema de notificaciones por correo
- [ ] Reglas personalizadas para detección

---

## 👨‍💻 Autor

Desarrollado por **[Phsyco]**  
🔗 GitHub: [https://github.com/AudiForze](https://github.com/AudiForze)  
📫 Contacto: *[geremygomez312@gmail.com]* o *[Discord: physco_0312]*

---

## 🛡️ Licencia

Este proyecto está licenciado bajo la **MIT License**.

```
MIT License

Copyright (c) 2025 Geremy

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia de este software y los archivos de documentación asociados (el "Software"), para utilizar el Software sin restricción, incluyendo sin limitación los derechos de usar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar y/o vender copias del Software, y permitir a las personas a quienes se les proporcione el Software que lo hagan, sujeto a las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las copias o partes sustanciales del Software.

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO PERO NO LIMITADO A GARANTÍAS DE COMERCIALIZACIÓN, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN.
```
