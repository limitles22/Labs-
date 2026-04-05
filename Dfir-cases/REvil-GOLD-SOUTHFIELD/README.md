# REvil – GOLD SOUTHFIELD | DFIR Analysis

**Plataforma:** CyberDefenders 

**Categoría:** Threat Hunting

**Dificultad:** Easy 

**Fecha:** 2025-04-05

---

# Executive Summary

Se identificó una intrusión de ransomware REvil mediante el análisis de logs de Sysmon ingestados en Elastic SIEM. El atacante entregó el ransomware a través 
de un ejecutable malicioso disfrazado de aplicación legítima (`facebook assistant.exe`), ubicado en la carpeta Downloads del Administrador — consistente con una técnica de engaño al usuario. 
Una vez en ejecución, el ransomware generó un proceso hijo de PowerShell para eliminar todas las Shadow Copies del sistema, saboteando la recuperación. 
Las notas de rescate fueron depositadas en múltiples directorios de usuario. La infraestructura de C2 utiliza un dominio onion de Tor, identificado 
mediante OSINT cruzando el hash de la muestra contra reportes públicos de sandbox.

---

# Tools Used

|**Splunk** | Análisis de logs |
|---|---|

---

