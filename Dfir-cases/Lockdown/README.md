# Lockdown — DFIR Analysis

Plataforma: CyberDefenders / HTB Sherlock
Categoría: Endpoint Forensics / Network Forensics / Malware Analysis / Threat Intel
Dificultad: Easy 
Fecha: 2025-04-01

---

# Executive Summary

Un atacante ingresó al sistema explotando una mala configuración de seguridad en un servidor web IIS, accediendo mediante enumeración SMB sin credenciales válidas. 
Una vez dentro, subió una webshell y la ejecutó para obtener acceso remoto. Además, instaló un ejecutable malicioso en la carpeta Startup de Windows para mantener persistencia, 
consistente con el comportamiento conocido de esta familia de malware (AgentTesla), orientada al robo de credenciales y exfiltración de información hacia su servidor de C2.

---

# Tools Used

|Herramienta | Propósito |
|---|---|
| **Wireshark** |Análisis de tráfico de red |
| **Volatility 3**  | Análisis de volcado de memoria |
| **PeStudio**      | Análisis estático de malware |
| **Virus Total** | Investigación OSINT |
| **MalwareBazaar** | Investigación OSINT | 

---

# Analysis 

## Reconnaissance

Se identificó un escaneo de puertos hacia el host víctima (10.0.2.15) originado desde 10.0.2.4. El patrón fue detectado en Wireshark → Statistics → Conversations → TCP, donde se observa que desde el puerto 55475 del atacante se enviaron exactamente 2 paquetes hacia múltiples puertos distintos de la víctima — comportamiento característico de un SYN scan (Nmap).

**MITRE: T1046 — Network Service Discovery**


### Initial Access

El atacante identificó el puerto 445 (SMB) abierto en el host víctima y realizó una enumeración de recursos compartidos para determinar cuáles estaban disponibles.

```
smb2.cmd == 3
```

Mediante este filtro en Wireshark se identificaron dos Tree Connect Requests hacia los siguientes shares:

| Share | Descripción |
|---|---|
| `\\10.0.2.15\IPC$` | Share especial de Windows usado para enumeración de recursos, usuarios y servicios. Accesible sin credenciales en configuraciones inseguras. |
| `\\10.0.2.15\Documents` | Share de archivos expuesto por IIS, con permisos de escritura que permitieron al atacante subir contenido malicioso. |

**Herramienta:** Wireshark  
**MITRE:** T1135 — Network Share Discovery

