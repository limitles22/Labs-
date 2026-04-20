# FalconEye Lab
**Plataforma:** CyberDefenders

**Categoría:** Incident Response / Threat Hunting

**Dificultad:** Medium

**Fecha:** 2026-04-20

---

## Executive Summary

En este laboratorio se investigó una brecha de seguridad en una red de Active Directory utilizando Splunk como SIEM. El atacante comprometió la cuenta `Abdullah-work\HelpDesk` en la máquina CLIENT02 y ejecutó una cadena de ataque completa que incluyó enumeración del dominio, escalación de privilegios, credential dumping, movimiento lateral, y acceso al dominio padre.

El análisis de telemetría Sysmon y Security logs en Splunk permitió reconstruir el kill chain completo: desde la enumeración inicial con BloodHound/SharpHound cargado en memoria vía PowerShell, la escalación de privilegios mediante explotación de una unquoted service path en el servicio `Automate-Basic-Monitoring.exe` (colocando `C:\program.exe` como binario malicioso), el uso de Mimikatz (`fun.exe`) para ejecutar DCSync contra la cuenta Administrator, ataques Over-Pass-The-Hash con Rubeus (`Microsoft-Update.exe`) para comprometer cuentas adicionales (Mohammed, it-support, Administrator), delegación Kerberos S4U para acceder a Client03 vía HTTP como Administrator, y finalmente la generación de un Golden Ticket inter-realm con SafetyKatz (`Better-to-trust.exe`) para acceder al controlador de dominio padre (`Ali.Alhakami`).

El atacante empleó múltiples técnicas de evasión: renombró Mimikatz como `fun.exe`, Rubeus como `Microsoft-Update.exe`, y SafetyKatz como `Better-to-trust.exe`. SharpHound fue cargado directamente en memoria mediante reflection para evitar tocar disco.

El ataque abarcó un período de aproximadamente 2 días (2023-05-09 — 2023-05-10) comprometiendo al menos tres sistemas: CLIENT02 (usuario HelpDesk), CLIENT03 (acceso como Administrator vía S4U), y el Domain Controller del dominio padre (acceso como Administrator vía Golden Ticket).

---

## Analysis

### Q1 — What is the name of the compromised account?

El enunciado describe escalación de privilegios vía unquoted service path, DCSync, PTH, y movimiento lateral. El primer paso es encontrar evidencia de actividad maliciosa para identificar la cuenta comprometida.

**Intento 1: buscar artefactos directos de DCSync y PTH**

Para DCSync:
```
index=* EventCode=4662 "1131f6ad" OR "1131f6aa"
```
Para PTH:
```
index=* EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
```

Ninguno devolvió resultados relevantes, los 4662 eran solo accesos a Group Policy y no había logons NTLM tipo 3.

**Intento 2: Sysmon Event ID 1 (Process Creation)**

Panorama general de cuentas:
```
index=* EventCode=1 | stats count by User | sort -count
```

<img width="1916" height="726" alt="image" src="https://github.com/user-attachments/assets/858da6e5-c3e1-4ca6-83bf-25dae7e904c7" />

Descartamos las cuentas de sistema (NT AUTHORITY\SYSTEM, NETWORK SERVICE, LOCAL SERVICE) y nos enfocamos en las cuentas de usuario: HelpDesk (140 eventos), Administrator, it-support, Mohammed, entre otras.

**Profundización en HelpDesk:**
```
index=* EventCode=1 User="Abdullah-work\\HelpDesk" Image="C:\\Users\\HelpDesk\\*"
| stats count by Image
```

<img width="1089" height="455" alt="image" src="https://github.com/user-attachments/assets/5c55a1a1-d8a6-45f0-bb8a-9a5ae93ec1d8" />

Esta query reveló múltiples indicadores de compromiso: binarios sospechosos en `C:\Users\HelpDesk\` (`Better-to-trust.exe`, `Microsoft-Update.exe`, `fun.exe`, `hfs.exe`, `http-server.exe`), herramientas de reconocimiento ejecutadas repetidamente (`whoami.exe` x14, `net.exe`/`net1.exe` x24, `klist.exe` x9), y `C:\calc.exe` en la raíz del disco fuera de su ubicación legítima.

**Respuesta:** Abdullah-work\HelpDesk

---

### Q2 — What is the name of the compromised machine?

Filtramos toda la actividad de la cuenta comprometida en Sysmon ID 1 y verificamos el campo `host`.

**Query:**
```
index=* EventCode=1 User="Abdullah-work\\HelpDesk"
| table _time, host
```

<img width="1574" height="700" alt="image" src="https://github.com/user-attachments/assets/eccd4b09-94da-4b8f-a304-2673803cb8f8" />

580 eventos, todos ejecutados desde la misma máquina. No hay dispersión en otros hosts.

**Respuesta:** CLIENT02

---

### Q3 — What tool did the attacker use to enumerate the environment?

**Intento 1: Sysmon ID 1 con campo Product**
```
index=* EventCode=1 User="Abdullah-work\\HelpDesk" Image="C:\\Users\\HelpDesk\\*"
| table _time, Image, Product
```

Identificamos Mimikatz (`fun.exe`), Rubeus (`Microsoft-Update.exe`), SafetyKatz (`Better-to-trust.exe`) y Http File Server (`hfs.exe`, `http-server.exe`). Ninguna es herramienta de enumeración.

**Intento 2: PowerShell Script Block Logging (Event ID 4104)**
```
index=* source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" host=CLIENT02 EventID=4104 "*BloodHound*"
| table _time, ScriptBlockText
| sort _time
```

<img width="1550" height="884" alt="image" src="https://github.com/user-attachments/assets/e62306ef-f45a-4a0f-894b-279dbfe93a34" />

Los logs mostraron el script completo de `Invoke-BloodHound`, el wrapper de PowerShell para SharpHound. El script carga el ingestor C# en memoria usando reflection (`assembly.load`) para evitar tocar disco, técnica de evasión (T1620 - Reflective Code Loading).

**Respuesta:** BloodHound

---

### Q4 — The attacker used an Unquoted Service Path to escalate privileges. What is the name of the vulnerable service?

Una unquoted service path requiere dos condiciones: ruta con espacios y sin comillas. Buscamos los comandos ejecutados con `sc.exe` en la máquina comprometida.

**Query:**
```
index=* EventCode=1 Image="*sc.exe*" host=CLIENT02
| table _time, CommandLine
```

<img width="1554" height="528" alt="image" src="https://github.com/user-attachments/assets/eca0e9af-7a75-4ffd-a052-83606027d7ad" />

**Resultado:** 7 eventos. Dos comandos `sc create` registran servicios con la ruta `C:\Program Files\Basic Monitoring\Automate-Basic-Monitoring.exe`. Esta ruta tiene espacios en `Program Files` y `Basic Monitoring`, haciéndola vulnerable. Los otros comandos (`sc start w32time`, `sc start wuauserv`) son servicios legítimos en System32.

**Respuesta:** Automate-Basic-Monitoring.exe

---

### Q5 — What is the SHA256 of the executable that escalates the attacker's privileges?

Buscamos la ejecución del servicio vulnerable para encontrar el hash del binario malicioso.

**Query:**
```
index="folks" host=CLIENT02 process="C:\\Program Files\\Basic Monitoring\\Automate-Basic-Monitoring.exe"
| table _time, Image, process, CommandLine, SHA256
```

<img width="1568" height="209" alt="image" src="https://github.com/user-attachments/assets/e22de5db-5bbc-40f2-aa53-e46eaaaad60c" />

4 eventos. El campo `Image` muestra `C:\program.exe` en todos los casos — confirmación directa de la explotación de la unquoted service path. Windows intentó resolver la ruta sin comillas y ejecutó `C:\program.exe` como primer intento.

**Respuesta:** 8ACC5D98CFFE8FE7D85DE218971B18D49166922D079676729055939463555BD2

---

### Q6 — When did the attacker download fun.exe?

Buscamos el Sysmon Event ID 11 (FileCreate) filtrando por archivos creados por PowerShell, ya que el atacante usó PowerShell para descargar las herramientas.

**Query:**
```
index=* User="Abdullah-work\\HelpDesk" Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" EventID=11
| table _time, Image, TargetFilename
| sort _time
```

<img width="1540" height="485" alt="image" src="https://github.com/user-attachments/assets/6f966227-b75e-4852-a6be-5670b64fa14b" />

Múltiples archivos creados por PowerShell. `C:\Users\HelpDesk\fun.exe` fue creado el 2023-05-10 a las 05:08:57. También se observa la creación de `Microsoft-Update.exe` (Rubeus) y múltiples scripts temporales `__PSScriptPolicyTest_*.ps1` (normales del funcionamiento de PowerShell).

**Respuesta:** 2023-05-10 05:08:57

---

### Q7 — What is the command line used to launch the DCSync attack?

Filtramos las ejecuciones de `fun.exe` (Mimikatz) para encontrar el comando DCSync.

**Query:**
```
index=* EventCode=1 User="Abdullah-work\\HelpDesk" Image="C:\\Users\\HelpDesk\\fun.exe"
| table _time, CommandLine
| sort _time
```

<img width="1228" height="553" alt="image" src="https://github.com/user-attachments/assets/efba442f-4112-48c4-9d0b-a7770fbeaf6c" />

10 eventos. Las primeras 9 ejecuciones son sin argumentos (modo interactivo). La última (2023-05-10 08:09:36) muestra el comando DCSync explícito usando el módulo `lsadump::dcsync` apuntando a la cuenta Administrator del dominio.

**Respuesta:** "C:\Users\HelpDesk\fun.exe" "lsadump::dcsync /user:Abdullah-work\Administrator"

---

### Q8 — What is the original name of fun.exe?

Sysmon Event ID 1 registra el campo `OriginalFileName` extraído de los metadatos del ejecutable (PE header), independientemente de cómo se renombre el archivo.

**Query:**
```
index=* EventCode=1 User="Abdullah-work\\HelpDesk" Image="C:\\Users\\HelpDesk\\fun.exe"
| table _time, CommandLine, OriginalFileName
```

<img width="1745" height="574" alt="image" src="https://github.com/user-attachments/assets/b1facaee-d634-483e-9e48-2f2c13cd45f1" />

10 eventos. Todos muestran `OriginalFileName: mimikatz.exe`, confirmando que `fun.exe` es Mimikatz renombrado — técnica de evasión para evitar detección por nombre de archivo (T1036.005 - Match Legitimate Name or Location).

**Respuesta:** mimikatz.exe

---

### Q9 — The attacker performed the Over-Pass-The-Hash technique. What is the AES256 hash of the account he attacked?

Over-Pass-The-Hash (OPTH) usa hashes AES de Kerberos para solicitar un TGT. Buscamos comandos que contengan "aes256" en los logs de creación de procesos.

**Query:**
```
index=* EventCode=1 host=CLIENT02 "*aes256*"
| table _time, CommandLine, Image
```

<img width="1908" height="476" alt="image" src="https://github.com/user-attachments/assets/f371a6df-57e1-4405-801d-0dcac82ea379" />

13 eventos mostrando múltiples ejecuciones de Rubeus (`Microsoft-Update.exe`) y SafetyKatz (`Better-to-trust.exe`). El primer comando cronológicamente (2023-05-10 05:49:10) es un `asktgt` contra la cuenta **Mohammed** con los flags `/opsec /createnetonly /ptt`, indicando el primer Over-Pass-The-Hash. El atacante usó el hash AES256 de Mohammed para solicitar un TGT y moverse lateralmente.

La cadena de compromiso sigue un orden lógico: HelpDesk → Mohammed (OPTH) → it-support (OPTH) → Administrator (DCSync) → Golden Ticket.

**Respuesta:** facca59ab6497980cbb1f8e61c446bdbd8645166edd83dac0da2037ce954d379

---

### Q10 — What service did the attacker abuse to access the Client03 machine as Administrator?

El atacante usó un ataque S4U (Service-for-User) — un mecanismo de delegación de Kerberos que permite a un servicio solicitar tickets en nombre de otro usuario.

**Query:**
```
index=* EventCode=1 host=CLIENT02 "*aes256*"
| table _time, CommandLine, Image
```

<img width="1568" height="257" alt="image" src="https://github.com/user-attachments/assets/2db2d138-efdc-4a02-ad6e-5ab4445fac32" />

El comando de las 2023-05-10 06:18:19 muestra un ataque S4U con Rubeus:
- `/user:Client02$` → cuenta de máquina de Client02
- `/msdsspn:http/Client03` → servicio objetivo: HTTP en Client03
- `/impersonateuser:Administrator` → impersona al Administrator
- `/ptt` → inyecta el ticket en la sesión actual

El atacante usó la cuenta de máquina de Client02 para solicitar un ticket del servicio HTTP en Client03, impersonando al Administrator.

**Respuesta:** http/Client03

---

### Q11 — The Client03 machine spawned a new process when the attacker logged on remotely. What is the process name?

Buscamos procesos creados en Client03 como Administrator después del ataque S4U (06:18:19).

**Query:**
```
index=* host=CLIENT03 user=Administrator EventCode=1 earliest="05/10/2023:06:18:19"
| table _time, Image, CommandLine
| sort _time
```

<img width="1475" height="458" alt="image" src="https://github.com/user-attachments/assets/1f0d46bb-4517-4838-a4e2-0c6d69992f9e" />

4 eventos. El primer proceso creado fue `wsmprovhost.exe` a las 06:21:44 con el argumento `-Embedding`. Este es el proceso que Windows lanza automáticamente cuando alguien se conecta remotamente vía WinRM/PowerShell Remoting (T1021.006). Confirma que el atacante usó el ticket HTTP del S4U para establecer una sesión remota.

Los procesos posteriores fueron reconocimiento: `HOSTNAME.EXE`, `whoami.exe`, y `mmc.exe` con `services.msc`.

**Respuesta:** wsmprovhost.exe

---

### Q12 — The attacker compromises the it-support account. What was the logon type?

El atacante usó Rubeus a las 06:49:48 para hacer OPTH con el hash AES256 de it-support, usando el parámetro `/createnetonly:C:\Windows\System32\cmd.exe`. Este parámetro crea un nuevo proceso con credenciales alternativas, generando un Logon Type 9 (NewCredentials).

**Query:**
```
index=* TargetUserName=it-support Caller_User_Name=HelpDesk EventID=4648
| table _time, host, TargetUserName, ProcessName
```

<img width="1621" height="637" alt="image" src="https://github.com/user-attachments/assets/b6c6ad0a-63b6-4753-ae2d-aaa1b7d64516" />

3 eventos en CLIENT02 (Event ID 4648 - logon con credenciales explícitas) mostrando que HelpDesk usó credenciales de it-support mediante fun.exe (Mimikatz) y PowerShell. El Logon Type 9 no aparecía en eventos 4624, pero los eventos 4648 confirmaron el uso de credenciales explícitas. El mecanismo `/createnetonly` de Rubeus genera un Logon Type 9 donde las credenciales no se validan localmente — solo se usan cuando el proceso accede a recursos de red.

**Respuesta:** 9 (NewCredentials)

---

### Q13 — What ticket name did the attacker generate to access the parent DC as Administrator?

El atacante necesitaba cruzar del dominio hijo (`Abdullah.Ali.Alhakami`) al dominio padre (`Ali.Alhakami`). Para esto generó un Golden Ticket inter-realm (trust ticket) usando SafetyKatz (`Better-to-trust.exe`) con el módulo `kerberos::golden`.

**Query:**
```
index=* EventCode=1 host=CLIENT02 "*kerberos::golden*"
| table _time, CommandLine
| sort _time
```

<img width="1841" height="571" alt="image" src="https://github.com/user-attachments/assets/878b12eb-1832-49b7-81f7-18b4bde3fa78" />

Dos comandos `kerberos::golden`:
1. (07:36:07) → generó `trust_tgt.kirbi` — primer intento/prueba
2. (08:06:47) → generó `trust-test2.kirbi` — ticket exitoso con parámetros adicionales (`/startoffset:0 /endin:600 /renewmax:10080 /ptt`)

El segundo ticket fue el que el atacante usó exitosamente para acceder al parent DC como Administrator, con parámetros de tiempo refinados.

**Respuesta:** trust-test2.kirbi

---

## Attack Timeline

| Tiempo (UTC) | Host | Evento |
|---|---|---|---|
| 2023-05-09 05:12:17 | CLIENT02 | hfs.exe (Http File Server) ejecutado por HelpDesk |
| 2023-05-09 08:24:12 | CLIENT02 | Servicio "Automation security monitoring tasks" creado con unquoted path |
| 2023-05-09 11:38:14 | CLIENT02 | Servicio "Monitoring service" creado con unquoted path |
| 2023-05-09 12:24:25 | CLIENT02 | `sc start Monitor` — servicio iniciado 
| 2023-05-09 12:25:45 | CLIENT02 | `C:\program.exe` ejecutado vía unquoted service path (hash original) |
| 2023-05-10 04:54:21 | CLIENT02 | PowerShell Script Block Logging registra SharpHound/BloodHound en memoria |
| 2023-05-10 04:57:36 | CLIENT02 | `C:\program.exe` ejecutado con hash modificado — escalación exitosa |
| 2023-05-10 05:08:57 | CLIENT02 | PowerShell descarga fun.exe (Mimikatz) |
| 2023-05-10 05:10:30 | CLIENT02 | Primera ejecución de fun.exe (modo interactivo) |
| 2023-05-10 05:45:11 | CLIENT02 | PowerShell descarga Microsoft-Update.exe (Rubeus) |
| 2023-05-10 05:49:10 | CLIENT02 | OPTH con Rubeus: asktgt /user:Mohammed /aes256:... |
| 2023-05-10 06:18:19 | CLIENT02 | S4U con Rubeus: impersonate Administrator en Client03 vía HTTP |
| 2023-05-10 06:21:44 | CLIENT03 | wsmprovhost.exe — sesión remota WinRM establecida como Administrator |
| 2023-05-10 06:23:37 | CLIENT03 | Reconocimiento: HOSTNAME.EXE, whoami.exe |
| 2023-05-10 06:49:48 | CLIENT02 | OPTH con Rubeus: asktgt /user:it-support /aes256:... (LogonType 9) |
| 2023-05-10 07:06:56 | CLIENT02 | fun.exe (Mimikatz) usa credenciales de it-support vía LDAP |
| 2023-05-10 07:16:39 | CLIENT02 | OPTH con Rubeus: asktgt /user:Administrator /aes256:... |
| 2023-05-10 07:36:07 | CLIENT02 | SafetyKatz genera Golden Ticket trust_tgt.kirbi (primer intento) |
| 2023-05-10 08:06:47 | CLIENT02 | SafetyKatz genera Golden Ticket trust-test2.kirbi — acceso a parent DC |
| 2023-05-10 08:09:36 | CLIENT02 | DCSync: lsadump::dcsync /user:Abdullah-work\Administrator |
| 2023-05-10 15:03:44 | CLIENT03 | mmc.exe services.msc — inspección de servicios |

---

## MITRE ATT&CK Mapping

| ID | Técnica | Detalle |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | SharpHound cargado en memoria, descarga de herramientas |
| T1087.002 | Account Discovery: Domain Account | BloodHound enumeró usuarios, grupos, ACLs, trusts |
| T1574.009 | Hijack Execution Flow: Unquoted Service Path | Explotación de ruta sin comillas colocando C:\program.exe |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Mimikatz → fun.exe, Rubeus → Microsoft-Update.exe, SafetyKatz → Better-to-trust.exe |
| T1003.006 | OS Credential Dumping: DCSync | lsadump::dcsync /user:Abdullah-work\Administrator |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | Over-Pass-The-Hash con hashes AES256 (Mohammed, it-support, Administrator) |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Trust ticket inter-realm (trust-test2.kirbi) para acceder al parent DC |
| T1021.006 | Remote Services: Windows Remote Management | WinRM para acceso remoto a Client03 (wsmprovhost.exe) |

---

## Conclusion

El análisis confirmó una brecha completa en un entorno de Active Directory multi-dominio. El atacante comprometió la cuenta HelpDesk en CLIENT02 y ejecutó una cadena de ataque que incluyó enumeración con BloodHound, escalación de privilegios vía unquoted service path, credential dumping con Mimikatz y SafetyKatz, ataques Kerberos avanzados (OPTH, S4U, Golden Ticket) con Rubeus, y acceso al dominio padre mediante un trust ticket inter-realm.
Las brechas principales fueron: un servicio con ruta sin comillas, ausencia de monitoreo de herramientas ofensivas, falta de segmentación de red, y delegación Kerberos mal configurada. Las mitigaciones recomendadas incluyen corregir rutas de servicios, implementar whitelisting de aplicaciones, configurar Credential Guard, restringir delegación Kerberos, y habilitar auditoría de Directory Services para detectar DCSync.

