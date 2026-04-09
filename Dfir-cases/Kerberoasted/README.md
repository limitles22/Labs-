# Kerberoasted Lab 

**Plataforma:** CyberDefenders 

**Categoría:** Threat Hunting  

**Dificultad:** Medium

**Fecha:** 2025-04-08

---

# Executive Summary

En este laboratorio se investigó una hipótesis de ataque Kerberoasting activo contra el dominio CYBERCACTUS.LOCAL. 
El análisis de logs del Domain Controller combinado con telemetría Sysmon permitió reconstruir la cadena completa del ataque desde el acceso inicial hasta el establecimiento de persistencia.
La investigación confirmó que el usuario johndoe ejecutó un ataque Kerberoasting exitoso desde 10.0.0.154, solicitando tickets de servicio con cifrado RC4-HMAC (0x17) para dos SPNs — SQLService y FileShareService. 
El hash de SQLService fue crackeado en aproximadamente 11 minutos, tras lo cual el atacante utilizó las credenciales comprometidas para acceder al DC, instalar un servicio malicioso con payload Meterpreter, 
habilitar RDP y establecer persistencia mediante una suscripción WMI denominada Updater.
El ataque abarcó un período de aproximadamente 21 minutos (07:37 — 07:58 UTC) y comprometió completamente el Domain Controller DC01.cybercactus.local, el activo más crítico del dominio.

---

# Analysis

Q1 — To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network?

Objetivo: Identificar el tipo de cifrado usado en los Kerberos Service Ticket Requests para evaluar la exposición a Kerberoasting.

Evento clave: Event ID 4769 — Kerberos Service Ticket Request.
Este evento registra cada solicitud de TGS e incluye el campo TicketEncryptionType, que indica el algoritmo de cifrado negociado.

Query:
```
index="kerberoasted" "winlog.event_id"=476
| stats count by winlog.event_data.TicketEncryptionType
```

<img width="1915" height="432" alt="image" src="https://github.com/user-attachments/assets/4aec28f0-e836-4683-a107-d282d2a52ce6" />


Hallazgo: Los 163 eventos de Event ID 4769 usan exclusivamente 0x17 (RC4-HMAC). En un entorno sano se esperaría una mezcla con AES (0x12/0x11). Ver únicamente RC4 indica que el entorno no tiene AES configurado, maximizando la superficie de ataque para Kerberoasting. RC4 permite que un atacante crackee offline el hash del ticket solicitado con herramientas como Hashcat o John the Ripper.

Respuesta: **RC4-HMAC (0x17)**


---

Q2 — What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short timeframe?

Objetivo: Identificar cuentas que solicitaron TGS para múltiples servicios en un intervalo corto — patrón característico de Kerberoasting automatizado.

Razonamiento: En Kerberoasting, el atacante solicita tickets de servicio para múltiples SPNs en rápida sucesión para crackearlos offline. Esto genera múltiples Event ID 4769 desde el mismo usuario en segundos.

Query:
```
index="kerberoasted" "winlog.event_id"=4769
| bin _time span=10s
| stats dc(winlog.event_data.ServiceName) as distinct_services,
        values(winlog.event_data.ServiceName) as services
  by _time, winlog.event_data.TargetUserName
| where distinct_services >= 2
```

<img width="1802" height="564" alt="image" src="https://github.com/user-attachments/assets/00000526-0848-45f8-84a4-10f55fe1e154" />


Hallazgo: johndoe@CYBERCACTUS.LOCAL solicitó TGS para SQLService y FileShareService con apenas milisegundos de diferencia (07:37:34.716 y 07:37:34.740). Este patrón de solicitudes simultáneas a múltiples SPNs es inconsistente con uso legítimo normal y es indicativo de enumeración automatizada de service accounts.

Respuesta: **johndoe**

---

