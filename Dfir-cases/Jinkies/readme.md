# DFIR Case Study – Jinkies Incident Analysis

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

Traducción realizada con la versión gratuita del traductor DeepL.com

---

## Which folders were shared on the host?

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

El análisis revelo dos carpetas siendo compartidas en la ruta "path" 

Respuesta: - `C:\Users\Velma\Documents` - `C:\Users`

