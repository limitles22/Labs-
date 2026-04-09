# Kerberoasted Lab 

**Plataforma:** CyberDefenders 

**Categoría:** Threat Hunting  

**Dificultad:** Medium

**Fecha:** 2026-04-08

---

# Executive Summary

En este laboratorio se investigó una hipótesis de ataque Kerberoasting activo contra el dominio CYBERCACTUS.LOCAL. 
El análisis de logs del Domain Controller combinado con telemetría Sysmon permitió reconstruir la cadena completa del ataque desde el acceso inicial hasta el establecimiento de persistencia.
La investigación confirmó que el usuario johndoe ejecutó un ataque Kerberoasting exitoso desde 10.0.0.154, solicitando tickets de servicio con cifrado RC4-HMAC (0x17) para dos SPNs — SQLService y FileShareService. 
El hash de SQLService fue crackeado en aproximadamente 11 minutos, tras lo cual el atacante utilizó las credenciales comprometidas para acceder al DC, instalar un servicio, habilitar RDP y establecer persistencia mediante una suscripción WMI denominada Updater.
El ataque abarcó un período de aproximadamente 21 minutos (07:37 — 07:58 UTC) y comprometió completamente el Domain Controller DC01.cybercactus.local, el activo más crítico del dominio.

---

# Analysis

Q1 — To mitigate Kerberoasting attacks effectively, we need to strengthen the encryption Kerberos protocol uses. What encryption type is currently in use within the network?

Event ID 4769 Kerberos Service Ticket Request.
Este evento registra cada solicitud de TGS e incluye el campo TicketEncryptionType, que indica el algoritmo de cifrado negociado.

Query:
```
index="kerberoasted" "winlog.event_id"=4769
| stats count by winlog.event_data.TicketEncryptionType
```

<img width="1915" height="432" alt="image" src="https://github.com/user-attachments/assets/4aec28f0-e836-4683-a107-d282d2a52ce6" />


Los 163 eventos de Event ID 4769 usan exclusivamente 0x17 (RC4-HMAC). En un entorno sano se esperaría una mezcla con AES (0x12/0x11). Ver únicamente RC4 indica que el entorno no tiene AES configurado, maximizando la superficie de ataque para Kerberoasting. RC4 permite que un atacante crackee offline el hash del ticket solicitado con herramientas como Hashcat o John the Ripper.

Respuesta: **RC4-HMAC (0x17)**


---

Q2 — What is the username of the account that sequentially requested Ticket Granting Service (TGS) for two distinct application services within a short timeframe?

En Kerberoasting, el atacante solicita tickets de servicio para múltiples SPNs en rápida sucesión para crackearlos offline. Esto genera múltiples Event ID 4769 desde el mismo usuario en segundos.

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

Q3 — We must delve deeper into the logs to pinpoint any compromised service accounts for a comprehensive investigation into potential successful kerberoasting attack attempts. 
Can you provide the account name of the compromised service account?

El 4769 solo confirma que el ticket fue solicitado, no que el ataque fue exitoso. Para confirmar compromiso hay que buscar actividad posterior de las service accounts atacadas, logins (4624), logoffs (4634), y actividad de procesos (Sysmon).

Query:
```
index="kerberoasted" SQLService
| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| where _time >= strptime("2023-10-16 07:37:00", "%Y-%m-%d %H:%M:%S")
| table time, winlog.event_id, winlog.event_data.TargetUserName, winlog.event_data.ServiceName
| sort time asc
```

<img width="1919" height="911" alt="image" src="https://github.com/user-attachments/assets/c2ec79cf-8799-40df-8845-78a245ea6088" />

11 minutos entre el TGS request y el primer logon de SQLService, consistente con crackeo offline de un hash RC4 con contraseña débil. 

<img width="1141" height="922" alt="image" src="https://github.com/user-attachments/assets/f179174a-80a4-470c-a423-d8f7f7bf4ff4" />

El evento 4624 expandido confirmó Logon Type 3 (red) con Elevated Token desde 10.0.0.154, usando NTLM, comportamiento anómalo para una service account de dominio.

Respuesta: **SQLService**

---

Q4 — To track the attacker's entry point, we need to identify the machine initially compromised by the attacker. What is the machine's IP address?

johndoe es la cuenta que ejecutó el Kerberoasting. Toda su actividad en los logs debería provenir de una única IP — la máquina comprometida.

Query:
```
index="kerberoasted" winlog.event_data.TargetUserName=johndoe@CYBERCACTUS.LOCAL
| table _time, winlog.event_data.IpAddress
```

<img width="1312" height="725" alt="image" src="https://github.com/user-attachments/assets/e674db1f-9b8a-4a95-bb7d-b7685cd3877e" />

Los 14 eventos asociados a johndoe provienen consistentemente de ::ffff:10.0.0.154. El prefijo ::ffff: es la representación IPv6 de una dirección IPv4, la IP real del atacante es 10.0.0.154.

Respuesta: **10.0.0.154**

---

Q5 — To understand the attacker's actions following the login with the compromised service account, can you specify the service name installed on the Domain Controller (DC)?

Tras un logon exitoso con credenciales crackeadas, el siguiente paso del atacante es establecer persistencia o ejecución remota. 
El Event ID 7045 registra instalación de nuevos servicios en Windows.

Query:
```
index="kerberoasted" winlog.event_id=7045
| table _time, winlog.event_data.ServiceName, winlog.event_data.ImagePath, winlog.event_data.AccountName
```

<img width="1919" height="273" alt="image" src="https://github.com/user-attachments/assets/953a6c62-9557-433f-956b-5d740ce8aec6" />

A las 07:48:10, en el mismo minuto del primer logon de SQLService, se instaló el servicio iOOEDsXjWeGRAyGl en DC01.cybercactus.local.

Respuesta: **iOOEDsXjWeGRAyGl**

---

Q6 — To grasp the extent of the attacker's intentions, What's the complete registry key path where the attacker modified the value to enable Remote Desktop Protocol (RDP)?

Tras obtener ejecución en el DC vía servicio malicioso, el atacante habilitó RDP para establecer acceso persistente e interactivo. El Sysmon Event ID 13 registra modificaciones de valores de registro.

Query:
```
index="kerberoasted" winlog.event_id=13
| search winlog.event_data.TargetObject="*Terminal Server*"
| table _time, winlog.event_data.TargetObject, winlog.event_data.Details
```

<img width="1676" height="587" alt="image" src="https://github.com/user-attachments/assets/27d2d7c7-716c-4684-a928-dbcb2f1b65e0" />

A las 07:48:38, 28 segundos después de instalar el servicio malicioso, SQLService modificó fDenyTSConnections a 0x00000000, habilitando RDP en el DC.
Este movimiento indica que el atacante buscaba acceso interactivo persistente más allá del shell inicial.

Respuesta: **HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections**

---

Q7 — To create a comprehensive timeline of the attack, what is the UTC timestamp of the first recorded Remote Desktop Protocol (RDP) login event?

Logon Type 10 corresponde específicamente a logins via Remote Interactive (RDP).

Query:
```
index="kerberoasted" "winlog.event_data.LogonType"=10
```

<img width="1896" height="841" alt="image" src="https://github.com/user-attachments/assets/44c6c35d-2af2-4cc8-863b-4909947ed172" />

El primer evento de Logon Type 10 ocurrió a las 07:50 UTC, apenas 72 segundos después de que el atacante habilitara RDP en el registro (07:48:38).

Respuesta: **2023-10-16 07:50**

---

Q8 — To unravel the persistence mechanism employed by the attacker, what is the name of the WMI event consumer responsible for maintaining persistence?

WMI persistence usa tres componentes — Event Filter (trigger), Event Consumer (acción) y Binding (los une). 
Sysmon Event IDs 19, 20 y 21 registran cada uno respectivamente.

Query:
```
index="kerberoasted" winlog.event_id IN (19, 20, 21)
| table _time, winlog.event_id, winlog.event_data.Name, winlog.event_data.Consumer, winlog.event_data.Filter
```

<img width="1896" height="841" alt="image" src="https://github.com/user-attachments/assets/b2792225-862b-4988-b2e0-1e5c7e34bab1" />

A las 07:58:06, 10 minutos después del primer login RDP, se registraron dos eventos con nombre Updater: Event ID 20 (Consumer) y Event ID 19 (Filter).
El nombre genérico es una técnica de camuflaje común. Al vivir en la base de datos WMI sin archivos en disco, esta técnica evade detección por antivirus tradicionales.

Respuesta: **Updater**

---

Q9 — Which class does the WMI event subscription filter target in the WMI Event Subscription you've identified?

El Event ID 19 registra el Filter WMI con su query completa en el campo winlog.event_data.Query.

Query:
```
index="kerberoasted" winlog.event_id IN (19, 20, 21) "winlog.event_data.Name"= \"Updater\"
| table _time, winlog.event_data.Query
```

<img width="1552" height="541" alt="image" src="https://github.com/user-attachments/assets/08e8b19b-e749-4773-ba81-2766128728a9" />

El Consumer se activa ante cada Event ID 4625 (failed logon) que mencione johndoe, mecanismo de detección de análisis forense que ejecuta una acción maliciosa si alguien intenta autenticarse como johndoe y falla.

Respuesta: **Win32_NTLogEvent**

---

# MITRE ATT&CK Mapping

| ID | Técnica | Detalle |
|---|---|---|
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | johndoe solicitó TGS con RC4 para SQLService y FileShareService |
| T1078 | Valid Accounts | Uso de credenciales crackeadas de SQLService para acceder al DC |
| T1569.002 | System Services: Service Execution | Instalación del servicio malicioso `iOOEDsXjWeGRAyGl` con payload PowerShell ofuscado, consistente con un stager Meterpreter |
| T1021.001 | Remote Services: Remote Desktop Protocol | Habilitación de RDP y acceso interactivo al DC |
| T1112 | Modify Registry | Modificación de `fDenyTSConnections` para habilitar RDP |
| T1546.003 | Event Triggered Execution: WMI Event Subscription | Persistencia mediante suscripción WMI `Updater` |
| T1027 | Obfuscated Files or Information | Payload PowerShell ofuscado con Base64 + GzipStream en el servicio malicioso |

---

# Conclusion

El análisis confirmó un ataque Kerberoasting exitoso contra el dominio CYBERCACTUS.LOCAL. 
El usuario `johndoe` solicitó tickets de servicio con cifrado RC4-HMAC (0x17) para `SQLService` y `FileShareService` desde `10.0.0.154`. 
El hash de `SQLService` fue crackeado en aproximadamente 11 minutos, tras lo cual el atacante utilizó las credenciales comprometidas para acceder al DC, 
instalar un servicio malicioso con payload PowerShell ofuscado, habilitar RDP y establecer persistencia mediante una suscripción WMI denominada `Updater`.

La raíz del problema fue la configuración de cifrado RC4 en las service accounts del dominio, 
que permitió el crackeo offline de credenciales. La mitigación principal es migrar a cifrado AES 
y aplicar contraseñas robustas en todas las service accounts.


