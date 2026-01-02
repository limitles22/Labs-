# Detroit Becomes Human Incident Analysis

## Overview

Se investiga un compromiso en el endpoint del usuario Alonzo Spire, quien fue víctima de una campaña de malware que suplantaba una herramienta de Inteligencia Artificial (Gemini).

A través de este análisis forense, reconstruiremos la línea de tiempo desde la infección inicial hasta la ejecución de payloads maliciosos y la posterior eliminación de pruebas por parte del usuario.

---

## Tools Used

- Hindsight: Análisis de historial de navegación (Chromium).

- TimelineExplorer: Visualización y filtrado de artefactos CSV/XML.

- MFTECmd (Zimmerman Tools): Análisis de la Master File Table ($MFT).

- Chainsaw: Búsqueda rápida y análisis de Event Logs (.evtx).

- Registry Explorer: Análisis de colmenas del registro de Windows.

- RBCmd: Análisis de archivos en la papelera de reciclaje ($Recycle.Bin).

---

## Case Questions & Analysis

---

Alonzo Spire está fascinado por la IA después de notar el reciente aumento en el uso de herramientas de IA para ayudar en las tareas diarias. 

Se encontró con una publicación patrocinada en las redes sociales sobre una herramienta de IA de Google. La publicación tuvo un gran alcance y la página que la publicó tenía más de 200 000 seguidores. 

Sin pensarlo dos veces, descargó la herramienta proporcionada a través de la publicación. Pero después de instalarla, no pudo encontrar la herramienta en su sistema, lo que le hizo sospechar.

Se notificó a un analista de DFIR un posible incidente en la máquina del administrador del sistema de Forela. 

Se le ha encomendado la tarea de ayudar al analista en el análisis para encontrar el verdadero origen de este extraño incidente.

---

## What is the full link of a social media post which is part of the malware campaign, and was unknowingly opened by Alonzo spire?

Para identificar el punto de inicio de la infección, analicé el historial de navegación del usuario utilizando Hindsight.

El objetivo fue convertir los artefactos del navegador a formato compatible con TimelineExplorer para su análisis visual.

```
python.exe .\hindsight.py -i "C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\Users\alonzo.spire\AppData\Local\Microsoft\Edge\User Data\Default" -o out
```

Luego de revisar todas las URLs visitadas, identifiqué una publicación sospechosa en Facebook que formaba parte de la campaña de malware.

<img width="1919" height="891" alt="image" src="https://github.com/user-attachments/assets/3ed9f179-ddbe-4795-9151-697fc5edbb4f" />

Respuesta: - `https://www.facebook.com/AI.ultra.new/posts/pfbid0BqpxXypMtY5dWGy2GDfpRD4cQRppdNEC9SSa72FmPVKqik9iWNa2mRkpx9xziAS1l`

---

## Can you confirm the timestamp in UTC when alonzo visited this post?

En la imagen podemos ver la hora en la que Alonozo visitó el post 

<img width="1919" height="891" alt="image" src="https://github.com/user-attachments/assets/f1aac88e-169b-4fd5-9047-206e1907607b" />

Respuesta: - `2024-03-19 04:30:00`

---

## Alonzo downloaded a file on the system thinking it was an AI Assistant tool. What is name of the archive file downloaded?

Continuando con el análisis temporal, identifiqué que poco después de visitar la publicación, el usuario descargó un archivo creyendo que se trataba de una herramienta legítima de IA.

<img width="1919" height="849" alt="image" src="https://github.com/user-attachments/assets/9573bab4-1f4b-4722-88db-f418af2dc4dc" />

Respuesta: - `C:\Users\alonzo.spire\Downloads\AI.Gemini Ultra For PC V1.0.1.rar`

---

## What was the full direct url from where the file was downloaded?

Al inspeccionar el evento de descarga dentro del historial del navegador, pude recuperar la URL directa desde la cual se obtuvo el archivo.

<img width="1919" height="887" alt="image" src="https://github.com/user-attachments/assets/52b6e677-7f18-4def-b504-f6cd3173cc9d" />

Respuesta: - `[https://drive.usercontent.google.com/download?id=1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H&export=download](https://drive.usercontent.google.com/download?id=1z-SGnYJCPE0HA_Faz6N7mD5qf0E-A76H&export=download)`

---

## Alonzo then proceeded to install the newly download app, thinking that its a legit AI tool. What is the true product version which was installed?

Inicialmente convertí la $MFT a CSV para identificar artefactos relevantes:

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\$MFT' --csv . --csvf mft_csv
```

Si bien no obtuve directamente la respuesta, el análisis reveló la presencia de un instalador MSI, lo que indicaba actividad del servicio Windows Installer.

Con esta información, busqué eventos MsiInstaller en los logs de Windows utilizando Chainsaw:

```
 chainsaw.exe search `
 "MsiInstaller" `
 "C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\Windows\System32\winevt\logs" --skip-errors
```

Correlacionando los eventos con el timestamp de la descarga, identifiqué la versión instalada.

<img width="1318" height="515" alt="image" src="https://github.com/user-attachments/assets/d654a032-e7b9-4a8b-acef-9b31c4e9e8b0" />

Respuesta: - `3.32.3`

---

## When was the malicious product/package successfully installed on the system?

Usando los mismos eventos de MsiInstaller, confirmé el momento exacto en que la instalación se completó exitosamente.

<img width="1318" height="515" alt="image" src="https://github.com/user-attachments/assets/c8e7d50d-7914-410a-982b-f951b0e6359b" />

Respuesta: - `2024-03-19 04:31:33`

---

## The malware used a legitimate location to stage its file on the endpoint. Can you find out the Directory path of this location?

Volví a analizar el CSV de la $MFT, esta vez filtrando por el nombre Install, lo que reveló una ruta utilizada para ocultar los archivos maliciosos.

<img width="1919" height="843" alt="image" src="https://github.com/user-attachments/assets/8884ad02-38b0-405a-9d96-84ff8aaab0d4" />

Respuesta: - `C:\Program Files (x86)\Google`

---

## The malware executed a command from a file. What is name of this file?

Filtrando por el parent path: `.\Program Files (x86)\Google\Install` 

identifiqué múltiples archivos. Por su extensión y propósito, el archivo encargado de ejecutar comandos era el siguiente. 

<img width="1918" height="627" alt="image" src="https://github.com/user-attachments/assets/da8f84ff-e7c0-430c-b32f-11edb6885b91" />

Respuesta: - `install.cmd`

---

## What are the contents of the file from question 8? Remove whitespace to avoid format issues.

Desde TimelineExplorer obtuve el Entry Number del archivo (51471-4) y utilicé MFTECmd para extraer su contenido directamente desde la $MFT. 

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\$MFT' --de 51471-4
```

<img width="1825" height="777" alt="image" src="https://github.com/user-attachments/assets/ee1e61e2-b25c-485d-9f70-ff5529092ef2" />

El contenido del archivo sin espacios es el siguiente.

Respuesta: - `@echooffpowershell-ExecutionPolicyBypass-File"%~dp0nmmhkkegccagdldgiimedpic/ru.ps1"`

---

## What was the command executed from this file according to the logs?

Dado que install.cmd ejecuta un script PowerShell (ru.ps1), busqué dicho script en los logs utilizando Chainsaw.

```
chainsaw.exe search `
"ru.ps1" `
"C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\Windows\System32\winevt" --skip-errors
```

<img width="1902" height="458" alt="image" src="https://github.com/user-attachments/assets/324acf24-8a32-451d-859e-afc9331c7d14" />

Respuesta: - `powershell -ExecutionPolicy Bypass -File C:\Program Files (x86)\Google\Install\nmmhkkegccagdldgiimedpic/ru.ps1`

---

## Under malware staging Directory, a js file resides which is very small in size.What is the hex offset for this file on the filesystem?

Aqui volvi a TimelineExplorer para ver el archivo .js que menciona la pregunta.

<img width="1917" height="700" alt="image" src="https://github.com/user-attachments/assets/faf3ce75-89cc-489d-bdd1-0af874d3b0e2" />

Este .js es el más pequeño asi que utilice su entry number “64067” y la herramienta MFTECmd para averiguat su offset.

```
MFTECmd.exe -f 'C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\$MFT' --de 64067-4
```

<img width="1903" height="846" alt="image" src="https://github.com/user-attachments/assets/b6dc5147-a641-4126-affe-0e2f13e8b988" />

Respuesta: - `3E90C00`

---

## Recover the contents of this js file so we can forward this to our RE/MA team for further analysis and understanding of this infection chain. To sanitize the payload, remove whitespaces.

Aquí utlice el mismo comando que la pregunta anterior y en la imagen podemos ver el payload. 

<img width="1898" height="627" alt="image" src="https://github.com/user-attachments/assets/d887f11a-8bdf-45d5-9339-8b1d7228258c" />

Respuesta: - `varisContentScriptExecuted=localStorage.getItem('contentScriptExecuted');
if(!isContentScriptExecuted){chrome.runtime.sendMessage({action: 'executeFunction'},
function(response){localStorage.setItem('contentScriptExecuted',true);});}`

---

## Upon seeing no AI Assistant app being run, alonzo tried searching it from file explorer. What keywords did he use to search?

Este tipo de actividad queda registrada en la clave WordWheelQuery del NTUSER.DAT por lo que utilicé RegistryExplorer para averiguarlo.

<img width="1875" height="943" alt="image" src="https://github.com/user-attachments/assets/61cd6608-0c2e-4424-953c-b309492be3bc" />

Se puede observar dentro de la ruta analizada `Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` la respuesta.

Respuesta: - ` Google Ai Gemini tool`

---

## When did alonzo searched it?

Desde la misma clave de registro obtuve el timestamp correspondiente.

<img width="1873" height="944" alt="image" src="https://github.com/user-attachments/assets/73a31145-c0cf-4a6f-a843-e71e473745eb" />

Respuesta: - `2024-03-19 04:32:11`

---

## After alonzo could not find any AI tool on the system, he became suspicious, contacted the security team and deleted the downloaded file. When was the file deleted by alonzo?

Finalmente, el usuario eliminó el archivo descargado.

Para analizar la papelera de reciclaje utilicé RBCmd.

```
RBCmd.exe -d 'C:\Users\limitles\Desktop\detroitbecomehuman\Triage\C\$Recycle.Bin'  --csv out_recycle
```

<img width="1919" height="900" alt="image" src="https://github.com/user-attachments/assets/dc8a44b7-b247-4f91-97cd-c909e92e8667" />

El timestamp correcto fue validado abriendo el CSV en TimelineExplorer, ya que RBCmd exporta la hora local.

<img width="1919" height="499" alt="image" src="https://github.com/user-attachments/assets/6bee7ace-1c9b-4beb-96f6-250d78110607" />

Respuesta: - `2024-03-19 04:34:16`

---

## Looking back at the starting point of this infection, please find the md5 hash of the malicious installer.

Luego de analizar los artefactos locales y no encontrar el hash directamente en el sistema, concluí que esta pregunta requería un enfoque OSINT.

Para ello, tomé el nombre del instalador identificado previamente en TimelineExplorer `Google AI Gemini Ultra For PC V1.0.1.msi` y lo busqué en Google. 

<img width="1210" height="774" alt="image" src="https://github.com/user-attachments/assets/5188001b-302b-4ab5-a541-cb5ad578da4d" />

La plataforma de AnyRun me dio la respuesta.

Respuesta: - `BF17D7F8DAC7DF58B37582CEC39E609D`
