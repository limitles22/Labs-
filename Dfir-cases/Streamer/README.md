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

Respuesta: - ´OBS-Studio-28.1.2-Full-Installer-x64.zip´



