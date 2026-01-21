# Streamer 

## Overview

Se investiga el compromiso del endpoint del usuario Simon Stark, un streamer que descargó un instalador malicioso que suplantaba software legítimo de OBS Studio.

A través de este análisis forense, se reconstruye la cadena completa de infección: desde la descarga inicial, el renombrado del archivo, la ejecución del instalador, la instalación del backdoor, los mecanismos de persistencia y la actividad de red asociada.

## Tools Used 

- MFTECmd – Análisis de $MFT y $UsnJrnl:$J
- EvtxECmd – Análisis de Event Logs de Windows
- AmcacheParser – Análisis del artefacto Amcache.hve
- PECmd – Análisis de archivos Prefetch
- SBECmd – Análisis de ShellBags desde NTUSER.DAT
- TimelineExplorer – Visualización y correlación temporal de artefactos CSV


## Context

Simon Stark es desarrollador en Forela y recientemente planeó transmitir algunas sesiones de programación con sus colegas, lo que le valió el reconocimiento del director general y otros compañeros. Sin saberlo, instaló un conocido software de transmisión que encontró mediante una búsqueda en Google y que era una de las URL más promocionadas por los anuncios de Google. Desafortunadamente, las cosas tomaron un giro inesperado y se produjo un incidente de seguridad. Analice los artefactos clasificados que se le proporcionan para averiguar qué sucedió exactamente.


## Case Question & Analysis


### What was the original ZIP file downloaded by Simon Stark?

Para identificar el archivo ZIP descargado, se analizó el artefacto $MFT, el cual contiene metadatos de todos los archivos creados y modificados en el sistema.

Se utilizó la herramienta MFTECmd para convertir el $MFT a formato CSV:

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\$MFT' --csv C:\output
```

Una vez generado el CSV, se filtraron los resultados por la extensión .zip. Entre los artefactos encontrados, se observó una ruta asociada al usuario Simon.Stark, confirmando que el análisis se realizaba en el contexto correcto.

<img width="1919" height="349" alt="image" src="https://github.com/user-attachments/assets/29177385-71c6-43bd-81c0-a25b76fab2ef" />

Sin embargo, el nombre del archivo identificado en el **$MFT** no corresponde al archivo final que se busca, ya que el **$MFT** no siempre refleja con claridad los eventos de renombrado.

Con el objetivo de identificar el cambio de nombre del archivo, repetí el análisis utilizando el **$UsnJrnl:$J**, que registra eventos de creación, modificación y renombrado de archivos.

Ejecuté el siguiente comando:

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\$Extend\$J' --csv c:\output
```

Luego, filtré los resultados por los términos “.zip” y “Obs”. En este caso, el $J muestra claramente los eventos de renombrado (RenameOldName / RenameNewName), permitiendo identificar el nombre original del archivo descargado antes de ser modificado por el usuario.

<img width="1919" height="619" alt="image" src="https://github.com/user-attachments/assets/fac315fb-6052-40db-b73a-510662fc1b18" />

Gracias a esta correlación, se puede confirmar el archivo original descargado.

Respuesta: - `OBS-Studio-28.1.2-Full-Installer-x64.zip`


##
### Simon Stark renamed the downloaded zip file. What's the renamed name and full path?

Para responder a esta pregunta, utilicé el timeline generado a partir del $MFT y del $UsnJrnl ($J), analizado previamente. En dicho timeline se observan eventos de RenameOldName y RenameNewName, lo que permite identificar con claridad el cambio de nombre del archivo descargado.

<img width="1919" height="597" alt="image" src="https://github.com/user-attachments/assets/f7e3623b-e575-4da8-a93c-e45a3d7027d4" />

El análisis muestra que el usuario **Simon Stark** renombró el archivo original

**`OBS-Studio-28.1.2-Full-Installer-x64.zip`**

a

**`Obs Streaming Software.zip`**.

Asimismo, el timeline indica que el archivo fue movido al siguiente directorio dentro del perfil del usuario:

Respuesta: - `C:\Users\Simon.stark\Documents\Streaming Software\Obs Streaming Software.zip`


##
### What's the timestamp when the file was renamed?

A partir del mismo evento de renombrado identificado en el $UsnJrnl:$J, se obtuvo el timestamp exacto del cambio de nombre.

<img width="1919" height="539" alt="image" src="https://github.com/user-attachments/assets/470da595-37e2-47bd-940b-bdf414f8692e" />

Respuesta: - `2023-05-05 10:22:23`


##
### What's the Full URL from where the software was downloaded?

Dentro del $MFT se identificó un Alternate Data Stream (ADS) llamado Zone.Identifier, asociado al archivo ZIP descargado.

Este ADS contiene metadatos relacionados con archivos descargados desde Internet. El valor ZoneId=3 confirma que el archivo proviene de una fuente externa (Internet).

Además, este stream preserva la URL de descarga original, permitiendo responder la pregunta con precisión.

<img width="1919" height="743" alt="image" src="https://github.com/user-attachments/assets/bba0204f-e1f6-4930-9c4f-4c4dbc7f1f3c" />

Respuesta: - `http://obsproicet.net/download/v28_23/OBS-Studio-28.1.2-Full-Installer-x64.zip`


##
### Dig down deeper and find the IP Address on which the malicious domain was being hosted.

Para identificar la dirección IP asociada al dominio malicioso, se analizaron los Event Logs de Windows utilizando EvtxECmd:

```
EvtxECmd.exe -d "C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\Windows\System32\winevt\Logs" --csv C:\output
```

A partir de este conjunto de eventos, se filtraron aquellos cuyo provider corresponde a `Microsoft-Windows-DNS-Client`.

Posteriormente, se aplicaron filtros adicionales por Event ID 3008, junto con el provider DNS y el payload que contiene el dominio `obsproicet.net`, ya que este identificador de evento indica que el sistema realizó una resolución DNS exitosa.

<img width="1903" height="366" alt="image" src="https://github.com/user-attachments/assets/553132a2-b8d8-4811-aad0-3cf30c4faf24" />

Como se observa en la imagen, el evento muestra la dirección IP resuelta para el dominio en cuestión, lo que permite identificar la infraestructura sobre la cual estaba alojado el dominio malicioso.

Respuesta: - `13.232.96.186`


##
### Multiple Source ports connected to communicate and download the malicious file from the malicious website. Answer the highest source port number from which the machine connected to the malicious website.

Para identificar el puerto de origen más alto utilizado por el host, se analizaron los logs del Firewall de Windows provistos en el reto, específicamente el archivo de texto `pfirewall`.

Este archivo contiene registros de las conexiones de red permitidas y bloqueadas, incluyendo las direcciones IP de origen y destino, así como los puertos de origen y destino.

<img width="1433" height="694" alt="image" src="https://github.com/user-attachments/assets/d4a16c55-f6a3-4d1a-85a1-6a18432cc568" />

Filtré por la ip obtenida de la pregunta anterior y fui recorriendo el archivo hasta encontrar el puerto mas alto.

Respuesta: - `50045`


##
### The zip file had a malicious setup file in it which would install a piece of malware and a legit instance of OBS studio software so the user has no idea they got compromised. Find the hash of the setup file.

Para identificar el archivo ejecutable malicioso contenido dentro del ZIP descargado por el usuario, se analizó el artefacto AMCache, el cual registra información sobre ejecutables y componentes de instalación que han sido ejecutados o instalados en el sistema.

Se procesó el archivo Amcache.hve utilizando AmcacheParser:

```
AmcacheParser.exe -f 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\Windows\AppCompat\Programs\Amcache.hve' --csv c:\output
```

<img width="1919" height="294" alt="image" src="https://github.com/user-attachments/assets/0a4b425c-f00e-4338-8dcc-32a07515de64" />

Filtrando con OBS, se identificó el ejecutable malicioso y su hash SHA1.

Respuesta: - `35e3582a9ed14f8a4bb81fd6aca3f0009c78a3a1`


##
### The malicious software automatically installed a backdoor on the victim's workstation. What's the name and filepath of the backdoor?

El malware instaló un backdoor adicional como parte del compromiso. Para identificarlo, se revisaron los CSV generados por Amcache, correlacionando por timestamp con la ejecución del instalador original.

<img width="1918" height="431" alt="image" src="https://github.com/user-attachments/assets/9eda94b3-e30e-4caf-9db4-434ee81651dd" />

El análisis reveló el siguiente ejecutable malicioso.

Respuesta: - `C:\Users\Simon.stark\Miloyeki ker konoyogi\lat takewode libigax weloj jihi quimodo datex dob cijoyi mawiropo.exe`


##
### Find the prefetch hash of the backdoor.

Se localizó el archivo Prefetch (.pf) correspondiente al backdoor y se analizó utilizando PECmd.

```
PECmd.exe -f 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\Windows\prefetch\LAT TAKEWODE LIBIGAX WELOJ JI-D8A6D943.pf'
```

<img width="839" height="621" alt="image" src="https://github.com/user-attachments/assets/70b6c0e7-e449-4ac6-bd61-c6956069c1c8" />

Podemos ver el hash en la imagen.

Respuesta: - `D8A6D943`


##
### The backdoor is also used as a persistence mechanism in a stealthy manner to blend in the environment. What's the name used for persistence mechanism to make it look legit?

Para identificar el mecanismo de persistencia, se analizaron los Event Logs de Windows, filtrando por Event ID 4698, el cual indica la creación de tareas programadas.

El backdoor creó una tarea con un nombre que simula un componente legítimo del sistema.

<img width="816" height="475" alt="image" src="https://github.com/user-attachments/assets/ba786f39-34d9-4bc2-92d3-dcaa6b84d226" />

Respuesta: - `COMSurrogate`


##
### What's the bogus/invalid randomly named domain which the malware tried to reach?

Utilizando nuevamente los logs DNS (Event ID 3008) y correlacionando la hora en la que se ejecutó el malware, se identificó un dominio con nombre aleatorio.

<img width="1919" height="396" alt="image" src="https://github.com/user-attachments/assets/f2c5fc30-270f-4ae2-a81d-98ca5ea153c6" />

<img width="817" height="475" alt="image" src="https://github.com/user-attachments/assets/5deb5aa8-77f0-43f5-b86f-cb08f5302785" />

Respuesta: - `oaueeewy3pdy31g3kpqorpc4e.qopgwwytep`


##
### The malware tried exfiltrating the data to a s3 bucket. What's the url of s3 bucket?

En los mismos eventos DNS, se identificaron resoluciones relacionadas con servicios de Amazon S3 filtrando por la palabra clave 'S3' en la columna Payload.

<img width="1919" height="306" alt="image" src="https://github.com/user-attachments/assets/59230ac2-6a5c-4412-a80b-5ca69b6be23b" />

<img width="816" height="477" alt="image" src="https://github.com/user-attachments/assets/5a160774-c5cb-448f-9f93-7efd2827fb7d" />

Respuesta: - `http://bbuseruploads.s3.amazonaws.com`


##
### What topic was simon going to stream about in week 1? Find a note or something similar and recover its content to answer the question.

Para responder esta pregunta, se analizaron archivos .txt dentro del perfil del usuario utilizando el $MFT.

Se identificó un archivo relevante en la carpeta de documentos del usuario, el cual fue recuperado directamente desde el $MFT.

<img width="1914" height="344" alt="image" src="https://github.com/user-attachments/assets/518f9cc2-462a-428e-8c59-b79cdb2dd4ea" />

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\$MFT' --de 5443 --ds 3
```

<img width="846" height="490" alt="image" src="https://github.com/user-attachments/assets/1bfc18f4-7ea7-41be-85b3-5dbf4c5d801c" />


Respuesta: - ` Filesystem Security`


##
### What's the name of Security Analyst who triaged the infected workstation?

Para identificar al analista, se analizaron los ShellBags del usuario Simon Stark utilizando SBECmd, los cuales registran rutas accedidas desde el Explorador de Windows.

```
SBECmd.exe -d 'C:\Users\limitles\Desktop\Streamer\Streamer\Acquisition\C\Users\Simon.stark\' --csv C:\output
```

<img width="1919" height="447" alt="image" src="https://github.com/user-attachments/assets/71ac7552-f2bf-450d-8152-07743a72f07b" />


El análisis reveló acceso a herramientas forenses alojadas en un recurso compartido perteneciente al analista.

Respuesta: - `CyberJunkie`


##
### What's the network path from where acquisition tools were run?

A partir del mismo análisis de ShellBags, se identificó la ruta completa desde donde se ejecutaron las herramientas de adquisición.

<img width="1919" height="387" alt="image" src="https://github.com/user-attachments/assets/8264a416-c0b0-4a32-a979-2c70ce868530" />

Respuesta: - `\\DESKTOP-887GK2L\Users\CyberJunkie\Desktop\Forela-Triage-Workstation\Acquisiton and Triage tools`
