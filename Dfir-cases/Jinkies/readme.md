# Jinkies Incident Analysis

## Overview

Este caso me llevó tiempo resolverlo, ya que requirió el uso de múltiples herramientas, investigación adicional sobre su funcionamiento y un enfoque de análisis metódico.

El proceso resultó especialmente enriquecedor y contribuyó a fortalecer mis habilidades como analista forense.

A continuación, presento el write-up completo del caso.

---

## Tools Commonly Used

- KAPE
- Chainsaw
- Impacket
- MFTECmd / PECmd
- Sysinternals Suite
- Hindsight
- PowerShell

---

## Case Questions & Analysis

---

Eres consultor externo de relaciones con inversionistas y tu jefe acaba de reenviarte un caso de una pequeña empresa emergente llamada cloud-guru-management ltd. Actualmente están desarrollando un producto con su equipo de desarrolladores, pero el director general ha recibido comentarios de que su propiedad intelectual ha sido robada y se está utilizando en otro lugar.

La usuaria en cuestión dice que puede haber compartido accidentalmente su carpeta de documentos y ha declarado que cree que el ataque se produjo el 6 de octubre. La usuaria también afirma que ese día no estaba delante de su computadora.

Aparte de esto, no hay mucha más información por parte de la empresa. Se ha iniciado una investigación sobre la causa principal de este posible robo a Cloud-guru; sin embargo, el equipo no ha logrado descubrir la causa de la filtración. Han reunido algunas pruebas preliminares para que las revises a través de un triaje KAPE. Depende de ti descubrir cómo se desarrolló todo esto.

Advertencia: este Sherlock requiere un elemento de OSINT y los jugadores tendrán que interactuar con servicios de terceros en Internet.



---

## Which folders were shared on the host? (Please give your answer comma separated, like this: c:\program files\share1, D:\folder\share2)

Para identificar las carpetas compartidas en el sistema, se analizaron los artefactos del Registro de Windows.

En sistemas Windows, los recursos compartidos se almacenan en la siguiente clave:

```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
```

Para localizar esta información dentro del conjunto de artefactos recolectados, se utilizó el siguiente comando en PowerShell:
```

Get-ChildItem . -Recurse -File |
Select-String"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares" 
```

<img width="1312" height="639" alt="image" src="https://github.com/user-attachments/assets/46a48791-5e15-4d0c-b3b2-3fdd46f43e48" />


El análisis revelo dos carpetas siendo compartidas dentro de la ruta "path" 


Respuesta: - `C:\Users\Velma\Documents` - `C:\Users`

---

## What was the file that gave the attacker access to the user's account?


Dado que el atacante tuvo acceso a la carpeta Documents del usuario Velma, se procedió a inspeccionar su contenido en busca de archivos que pudieran contener credenciales.


Se listaron los archivos presentes:

```
Get-ChildItem "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Documents" -Recurse -File
```

Posteriormente, se filtraron archivos que contuvieran la palabra password:

```
Get-ChildItem "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Documents" -Recurse -File | Select-String 'password'
```

<img width="1839" height="722" alt="image" src="https://github.com/user-attachments/assets/547e2c32-daaa-4663-81bf-cab08f088ce1" />


Se puede ver en el primer resultado, un archivo .ibd, correspondiente a una base de datos MySQL comunmente utilizada para almacenar datos estructurados. 


Decidí por ver lo que habia dentro del archivo, por lo que, primero tuve que confirmar su ubicación:

```
Get-ChildItem "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output" ` -Recurse -File -Filter "bk_db.ibd" | Select-Object FullName
```

Para luego usar: 

```
strings.exe "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Documents\Python Scripts + things\web server project\testing\logon website\bk\bk_db.ibd"
```

<img width="1464" height="754" alt="image" src="https://github.com/user-attachments/assets/1c036dce-d7a2-4b04-9b28-14b6829ced64" />


EL archivo contiene usuarios y contraseñas.


Respuesta:  `bk_db.ibd`

---

## How many user credentials were found in the file?


Para determinar cuántas credenciales estaban almacenadas en el archivo, se extrajeron cadenas legibles utilizando strings.exe y se filtraron direcciones de correo electrónico:

```
strings.exe "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Documents\Python Scripts + things\web server project\testing\logon website\bk\bk_db.ibd" | Select-String "@" | Measure-Object
```


<img width="1720" height="156" alt="image" src="https://github.com/user-attachments/assets/2fd3f2ba-48ec-44e3-bc2d-c841bf993684" />


Respuesta: `216`

---

## What is the NT hash of the user's password?

Al tratarse de una cuenta local, el hash NT del usuario Velma se encuentra en el hive SAM, protegido mediante la BootKey almacenada en el hive SYSTEM.

Se utilizó la herramienta Impacket–secretsdump para extraer la información:

```
python.exe 'C:\Users\limitles\tools\impacket\examples\secretsdump.py' -sam "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\Windows\system32\config\SAM" -system "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\Windows\system32\config\SYSTEM" LOCAL
```

<img width="1909" height="184" alt="image" src="https://github.com/user-attachments/assets/aa5d42a2-9895-4228-850a-ff6e7364a109" />

Podemos ver el NT hash del usuario.

Respuesta: `967452709ae89eaeef4e2c951c3882ce`

---

## Is the user's computer password the same as the password found in the ibd file? (Yes or No)

Para validar si ambas contraseñas coincidían, se extrajo la contraseña del archivo bk_db.ibd:

```
strings.exe "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Documents\Python Scripts + things\web server project\testing\logon website\bk\bk_db.ibd" | select-string "velma"
```

<img width="1857" height="82" alt="image" src="https://github.com/user-attachments/assets/7c55e140-5a30-4056-a2e7-224225591579" />

Para hashear la contraseña de velma: `peakTwins2023fc`, utilice el generador de hashes Code Beautify 

<img width="978" height="748" alt="image" src="https://github.com/user-attachments/assets/7b76302e-3797-471c-b97c-373463f338ad" />


Podemos ver que el hash generado coincide con el anterior.


Respuesta: `Yes`


---

## What was the time the attacker first interactively logged on to our user's host?

La respuesta a esta pregunta lo obtendriamos analizando logs. 
Pude utilizar el visor de eventos de Windows, pero, decidi optar por Chainsaw. 

Utilice dos filtros, uno el evento 4624 de logon exitoso. 
Segundo, el logon type 3. Este hace referencia a un inicio de sesion remota a través de la red.

```
chainsaw.exe search `
-t "Event.System.EventID: =4624" -t "Event.EventData.LogonType: =3" `
"C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\Windows\system32\winevt\logs" --skip-errors
```

<img width="702" height="744" alt="image" src="https://github.com/user-attachments/assets/9f64c5c9-c623-4d07-8b3d-f859cd26c9b6" />

Este evento contiene la información que necesitamos.

Respuesta: `2023-10-06 17:17:23`

---

## What's the first command the attacker issues into the Command Line?


Para responder esta pregunta decidi usar Chainsaw y filtrar por: 
hora en la que el atacante accedio al host remotamente y por la palabra 'cmd.exe' 
ya que nos interesa saber que comando ingreso.

```
chainsaw.exe search `
--timestamp "Event.System.TimeCreated_attributes.SystemTime" --from "2023-10-06T17:17:23"`
"cmd.exe" `
"C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\Windows\system32\winevt\logs" --skip-errors
```

<img width="1232" height="699" alt="image" src="https://github.com/user-attachments/assets/acb783cb-2a5a-4249-a283-4c4a668eded5" />


De los 19 resultados, el segundo contiene la información que necesitamos.

Respuesta: `whoami`

---

## What is the name of the file that the attacker opens in VSCode shortly before launching the web browser?


Para responder esta pregunta decidí seguir con Chainsaw y aplicar estos filtros:

```
chainsaw.exe search `
--timestamp "Event.System.TimeCreated_attributes.SystemTime" --from "2023-10-06T17:17:23" `
"cmd.exe" `
"Code.exe" `
"C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\Windows\system32\winevt\logs" --skip-errors
```

Priorice filtrar 'cmd.exe' sobre 'Code.exe' porque este patrón, en el cual Code es el padre de cmd, 
indica que abrio un archivo dentro de VS Code, usó el terminal integrado y ejecuto comandos.

<img width="1473" height="703" alt="image" src="https://github.com/user-attachments/assets/97c28930-db16-433f-9069-135c8aabfc67" />


En este evento podemos ver cual es el archivo.

Respuesta: `Version-1.0.1 - TERMINAL LOGIN.py`

---

## What's the domain name of the location the attacker likely exfiltrated the file to?

Esta información podemos encontrarla en el archivo History de Google Chrome.
Decidi usar la herramienta Hindsight para convertir el archivo History a .xlsx y poder visualizarlo en TimelineExplorer

```
python.exe .\hindsight.py -i "C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\users\Velma\Appdata\Local\Google\Chrome\User Data\Default" -o out
```

En TimelineExplorer filtre por la fecha en el que el atacante accedio al host 

<img width="1273" height="642" alt="image" src="https://github.com/user-attachments/assets/8717a46f-4d78-450a-885a-185248ef19d8" />

Esta url generalmente contiene código fuente, scripts y de más que los atacantes utilizan. 

Respuesta: `pastes.io`

---

## What is the handle of the attacker?

En general, en estos laboratorios, el hanlde o "firma" del atacante podemos encontrarlo en archivo dentro del sistema con extensiones como:
.txt o scripts (.ps1, .py).
Decidí usar MFTECMD para convertir el archvio $MFT (es la base de datos central del sistema de archivos NTFS) 
a un formato visible en TimelineExplorer 

```
MFTECMD.exe -f 'C:\Users\limitles\Desktop\jinkies\Jinkies_KAPE_output\TriageData\C\$MFT' --csv . --csvf mft.csv
```

Ya con el .csv en manos, dentro de TimelineExplorer filtre por Parent Path, Extension y Created 0x10 

<img width="1274" height="696" alt="image" src="https://github.com/user-attachments/assets/51e8a87e-f4b8-4d8f-b095-e5221ff7220c" />

El archivo 'learn.txt' fue el primero creado desde el path .\Users\Velma\Pictures a las 17:23:46.
Minutos después del logon en el host. 

Si bien el $MFT permite identificar la existencia del archivo, su ruta, timestamps y metadatos NTFS, no almacena de forma directa el contenido completo del archivo.

Para intentar recuperar el contenido del archivo, fue necesario analizar el $MFT a nivel binario, utilizando 010 Editor.

Para ubicar el registro del archivo en MFT use el siguiente comando en powershell:

```
Import-Csv C:\Users\limitles\mft.csv |
Where-Object { $_.FileName -eq "learn.txt" } |
Format-List
```

<img width="846" height="561" alt="image" src="https://github.com/user-attachments/assets/06e7e204-7a78-42fd-b2cf-61173143765b" />


De aquí obtenemos el entrynumber: 78533.

El Entry Number es el identificador único de un registro dentro del $MFT (Master File Table).

Cada archivo o directorio en NTFS tiene asignado un registro MFT, y el Entry Number indica qué posición ocupa ese registro dentro del $MFT.

El $MFT es un archivo binario, y herramientas como 010 Editor trabajan con offsets en hexadecimal.

Por eso, para ubicar manualmente un registro MFT específico, es necesario convertir el Entry Number (decimal) a hexadecimal.

```
'{0:X8}' -f 80417792
```

Ese comando toma un Entry Number en decimal, lo convierte a hexadecimal, 

y lo presenta con el formato correcto para trabajar con el $MFT en herramientas hexadecimales como 010 Editor.


<img width="1036" height="783" alt="image" src="https://github.com/user-attachments/assets/b120f682-cca8-42b2-98df-cfbc37d20ac3" />


Ahora si, podemos observar el handle o firma del atacante.

Respuesta: `pwnmaster12`

