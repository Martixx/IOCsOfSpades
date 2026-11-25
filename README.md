# IOCs of Spades — 2.2 "Lemmy"
**BORN TO SCAN // LIVE TO WIN**  
**🤘 Everything louder than everything else 🤘**

IOCs of Spades es una macarrada para automatizar:
- Búsqueda y análisis de IOCs  
- Consultas OSINT  
- VirusTotal API  
- Passive DNS  
- Exportación masiva de indicadores  
- Checks anti‑MITM (detector de proxies tipo Zscaler, ForwardTrust, VPN intercept…)  
- Modos de pausa/reanudar para análisis largos  

Forjada escuchando a Lemmy Kilmister, no muy rápida, pero siempre ruidosa. (Ojo con algunas opciones que te petan la API)

------------------------------------------------------------
FEATURES
------------------------------------------------------------

- Automatización OSINT (IPs, dominios, hashes)
- Detección automática de interceptación SSL/mitm
- Passive DNS + VirusTotal
- Modo Tor / Onionoo
- Caché OSINT local
- Pausar y reanudar análisis
- Exportación de análisis a CSV
- Compatible con Linux y Windows

------------------------------------------------------------
REQUISITOS
------------------------------------------------------------

Python:
Se requiere Python 3.10 o superior.

En Linux (Debian/Ubuntu):
    sudo apt install python3 python3-pip

En Windows:
    Descargar desde https://www.python.org/downloads/

Dependencias:
    pip install requests tqdm

------------------------------------------------------------
SETUP RÁPIDO PARA MANCOS
------------------------------------------------------------

1. Crear un archivo llamado IOCS-apikeys.txt en la misma carpeta.
   Puedes copiar la plantilla incluida en el repo:
      IOCS-apikeys.example.txt

   Formato recomendado (KEY=valor):
      VT=tu_vt_key_1
      VT=tu_vt_key_2
      ABUSEIPDB=tu_abuseipdb_key_1,tu_abuseipdb_key_2
      ABUSECH=tu_abusech_key_1,tu_abusech_key_2
      OTX=tu_otx_key_1,tu_otx_key_2

   Notas:
   - VT también acepta formato legado sin prefijo (una key por línea).
   - Para ABUSEIPDB/ABUSECH/OTX puedes usar varias claves separadas por coma,
    punto y coma o espacios.
   - Nunca subas IOCS-apikeys.txt con claves reales.

2. (Opcional) Crear archivos de listas:
       iplist.txt
       dominios.txt
       hashes.txt

   Pueden estar vacíos o contener listas de IOCs.

3. Instalar dependencias:
       pip install requests tqdm

4. Ejecutar la herramienta:

   En Linux:
       python3 IOCsOfSpades.py

   En Windows:
       python IOCsOfSpades.py

5. Notas importantes:
   - Sin IOCS-apikeys.txt, sólo funcionarán modos OSINT (VT necesitará una key).
   - La carpeta .osint_cache/ se genera automáticamente.
   - Si el banner se descuadra en CMD, usar Windows Terminal o terminal de VS Code.

------------------------------------------------------------
MODOS PRINCIPALES
------------------------------------------------------------

IP MODE:
- VirusTotal
- Passive DNS
- OSINT
- ASN-DROP: IP-API is primary; local IPtoASN is the fallback (IPs are sent to IP-API).
- Tor mode
- Exportación a CSV
- Reanudar desde checkpoint

DOMAIN MODE:
- VT list
- OSINT
- Reanudar

HASH MODE:
- VT (single / list)
- MalwareBazaar
- Reanudar

EXTRAS:
- Menú de debug
- Sugerencias de IP recientes
- Caché persistente

------------------------------------------------------------
PREGUNTAS FRECUENTES (FAQ)
------------------------------------------------------------

1. ¿Qué necesita la herramienta para funcionar?
   - Python 3.10+
   - pip install requests tqdm
   - Archivo IOCS-apikeys.txt con tus claves de VT

2. ¿Dónde pongo las claves de VirusTotal?
   En IOCS-apikeys.txt.
   Revisa la plantilla IOCS-apikeys.example.txt para el formato completo.

3. ¿Necesito iplist.txt / dominios.txt / hashes.txt?
   Opcional. Pueden estar vacíos, pero lo suyo es que consultes IOCs y en algún sitio los tendrás que meter. Digo yo.

4. ¿Puedo usar la herramienta sin API keys?
   Sí. Funciona el modo OSINT.  
   VirusTotal requerirá una API key.

5. ¿Funciona en Linux?
   Sí. Incluso mejor que en Windows.

6. ¿Funciona en Windows?
   Sí.  
   Se recomienda Windows Terminal o terminal de VS Code.

7. ¿Dónde se guarda la caché OSINT?
   En la carpeta .osint_cache/.

8. ¿Se pueden usar varias claves de VT?
   Sí. Es recomendable para rotar y evitar límites.

9. ¿Por qué se detiene el análisis?
   Usa un sistema de pausa/reanudar mediante checkpoints. Si tiras una consulta enorme y por lo que sea tienes que levantar una VPN, lo puedes parar y luego reanudar. 

10. ¿Por qué sale mensaje de MITM?
    El script detecta proxies corporativos, SSL intercept, etc. Es la protección anti-mancos por si te has dejado una VPN encendida y no llegas a la API de VT.

11. ¿Qué exporta?
    Resultados en CSV con timestamp.

12. ¿Es portable?
    Sí. No requiere instalación, bases de datos ni demonios.

------------------------------------------------------------
LICENSE
------------------------------------------------------------

Este proyecto está bajo Apache License 2.0.
Free to use, modify, and share — built for noise, chaos, and overdrive.
El texto completo de la licencia está en LICENSE.txt.

------------------------------------------------------------
AUTORÍA TÉCNICA
------------------------------------------------------------

Proyecto creado con fines técnicos, formativos y operativos.  
Diseñado para analistas, SOCs y equipos de respuesta que necesitan
automatizar consultas y análisis OSINT cagando melodías.

------------------------------------------------------------
