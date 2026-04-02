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

| **Wireshark** |Análisis de tráfico de red |
|---|---|
| **Volatility 3**  | Análisis de volcado de memoria |
| **PeStudio**      | Análisis estático de malware |
| **Virus Total** | Investigación OSINT |
| **MalwareBazaar** | Investigación OSINT | 



---
