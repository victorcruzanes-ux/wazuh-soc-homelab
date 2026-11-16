# Detección de intentos de autenticación SSH no autorizados con Wazuh SIEM

**Proyecto:** Wazuh SIEM Home Lab  
**Área:** Blue Team / Security Operations Center (SOC)  
**Tipo de ejercicio:** Detección y análisis de eventos de autenticación  
**Nivel:** Junior  
**Fecha de realización:** 11 de noviembre de 2026  
**Estado:** Validado en laboratorio

---

## 1. Resumen ejecutivo

En este escenario se ha desplegado y configurado un entorno de laboratorio con Wazuh SIEM para monitorizar eventos de seguridad relacionados con el servicio SSH.

El objetivo ha sido comprobar la capacidad de Wazuh para detectar intentos de autenticación no autorizados contra un servidor Linux, analizar las alertas generadas e identificar los eventos relevantes para un analista SOC.

La prueba se ha realizado desde una máquina Kali Linux contra un servidor Wazuh, utilizando un nombre de usuario inexistente. El intento generó eventos de autenticación fallida que fueron recogidos por el sistema de monitorización y procesados por las reglas de detección de Wazuh.

Durante la validación se identificó también un problema de duplicidad en la ingesta de registros: los eventos SSH estaban siendo recopilados simultáneamente desde `journald` y `/var/log/auth.log`. Se corrigió la configuración para mantener una única fuente de recopilación y evitar alertas duplicadas.

**Resultado:** se validó la detección de eventos SSH mediante las reglas 5710 y 5503 de Wazuh, y se comprobó que, tras corregir la configuración, los nuevos eventos se procesaban una sola vez desde `journald`.

> Importante: el ejercicio demuestra la detección de un intento controlado de autenticación fallida. No constituye una prueba de fuerza bruta sostenida ni permite evaluar la detección de múltiples intentos correlacionados.

## 2. Objetivos

### Objetivo principal

Implementar y validar un escenario básico de detección de actividad de autenticación SSH no autorizada utilizando Wazuh como plataforma SIEM.

### Objetivos específicos

- Preparar una comunicación de red entre el equipo atacante y el servidor monitorizado.
- Verificar que el servicio SSH está disponible.
- Comprobar la generación de registros de autenticación en el servidor.
- Configurar Wazuh para recopilar los eventos relevantes.
- Ejecutar una prueba controlada de autenticación fallida.
- Identificar y analizar las alertas generadas.
- Relacionar las detecciones con MITRE ATT&CK.
- Identificar y corregir la duplicidad en la ingesta de eventos.
- Validar nuevamente el escenario tras el ajuste de configuración.

## 3. Arquitectura del laboratorio

El entorno se ha desplegado mediante máquinas virtuales utilizando Oracle VirtualBox.

| Componente | Descripción | Dirección IP |
|---|---|---|
| Equipo anfitrión | Windows 11 | — |
| Máquina de pruebas | Kali Linux Rolling 2025.4 | 10.10.10.20 |
| Servidor SIEM | Wazuh Server | 10.10.10.10 |

### Topología de red

Ambas máquinas virtuales disponen de una interfaz NAT y una segunda interfaz conectada a una red interna de VirtualBox denominada `CYBER-SOC`.

La comunicación entre los equipos del laboratorio se realiza a través de la red interna:

- Kali Linux: `10.10.10.20`
- Wazuh Server: `10.10.10.10`

El servicio SSH del servidor está disponible en el puerto TCP 22.

### Tecnologías utilizadas

- Oracle VirtualBox 7.2.4.
- Kali Linux Rolling 2025.4.
- Wazuh 4.14.10.
- Wazuh Manager.
- Wazuh Agent.
- OpenSSH.
- Systemd Journal (`journald`).
- Terminal Linux.

## 4. Preparación y comprobaciones iniciales

Antes de realizar la prueba se verificó la conectividad y disponibilidad del servicio SSH.

### 4.1. Comprobación del servicio SSH

**Equipo:** Wazuh Server.

Se comprobó que el servicio SSH estaba iniciado:

```bash
sudo systemctl is-active ssh
```

**Resultado esperado y obtenido:**

```text
active
```

A continuación, se verificó que el servidor escuchaba en el puerto TCP 22:

```bash
sudo ss -ltnp | grep ':22'
```

Se confirmó que el servicio estaba escuchando en las interfaces IPv4 e IPv6.

### 4.2. Comprobación de conectividad

**Equipo:** Kali Linux.

Se comprobó la disponibilidad del puerto SSH del servidor:

```bash
nc -zv 10.10.10.10 22
```

La conexión TCP se estableció correctamente y el puerto 22 respondió como abierto.

### 4.3. Verificación del agente Wazuh

Se comprobó que el agente instalado en Kali Linux figuraba como activo en Wazuh.

El entorno contaba con los siguientes registros:

- `000`: Wazuh-Server — Active / Local.
- `001`: Kali-Linux — Active.

## 5. Configuración de la monitorización

Para detectar los eventos de autenticación se revisó la configuración del sistema Wazuh.

El archivo principal de configuración utilizado fue:

```text
/var/ossec/etc/ossec.conf
```

Inicialmente se identificó un problema estructural en el XML: existían dos elementos raíz `<ossec_config>`, lo que provocaba un error de análisis.

Se corrigió la estructura para mantener un único elemento raíz y se validó el archivo.

Posteriormente, se comprobó la configuración del Logcollector mediante:

```bash
sudo /var/ossec/bin/wazuh-logcollector -t
```

La validación finalizó correctamente.

También se confirmó que Wazuh estaba analizando los registros de autenticación mediante `journald`.

En esta fase se verificó que el servicio Wazuh Manager permanecía activo tras aplicar los cambios.

## 6. Ejecución de la prueba controlada

### 6.1. Descripción

Se realizó un intento controlado de conexión SSH utilizando un nombre de usuario inexistente.

**Equipo de origen:** Kali Linux  
**Equipo de destino:** Wazuh Server  
**Dirección de destino:** `10.10.10.10`  
**Servicio:** SSH  
**Puerto:** TCP 22  
**Usuario utilizado:** `usuario_falso`

### 6.2. Comando ejecutado

**Equipo:** Kali Linux.

```bash
ssh usuario_falso@10.10.10.10
```

Se intentó realizar la autenticación con un usuario inexistente y se produjo un fallo de autenticación.

### 6.3. Comprobación en el servidor

**Equipo:** Wazuh Server.

Se revisaron los registros de autenticación:

```bash
sudo tail -n 50 /var/log/auth.log
```

Entre los eventos observados se encontraron:

- `Invalid user usuario_falso`
- `pam_unix(sshd:auth): authentication failure`
- `Failed password for invalid user usuario_falso`

Estos registros confirmaron que el servidor SSH había recibido la conexión y que el proceso de autenticación había fallado.

## 7. Detecciones generadas por Wazuh

Tras la ejecución de la prueba, Wazuh generó alertas relacionadas con los eventos de autenticación.

Se identificaron dos reglas principales:

### 7.1. Regla 5710 — Intento de acceso con usuario inexistente

| Campo | Resultado |
|---|---|
| Rule ID | 5710 |
| Nivel | 5 |
| Descripción | sshd: Attempt to login using a non-existent user |
| Origen | 10.10.10.20 |
| Destino | 10.10.10.10 |
| Usuario | usuario_falso |

Esta regla identifica intentos de autenticación SSH utilizando una cuenta que no existe en el sistema.

Se observaron eventos correspondientes a la identificación del usuario inexistente y al posterior fallo de contraseña.

### 7.2. Regla 5503 — Fallo de autenticación PAM

| Campo | Resultado |
|---|---|
| Rule ID | 5503 |
| Nivel | 5 |
| Descripción | PAM: User login failed |
| Origen | 10.10.10.20 |
| Evento | Fallo de autenticación |

Esta regla identifica un fallo de autenticación gestionado por PAM (Pluggable Authentication Modules).

Su activación permitió confirmar que el fallo de acceso también había sido registrado por el mecanismo de autenticación del sistema.

### 7.3. Relación con MITRE ATT&CK

Las reglas identificadas incluyen las siguientes referencias:

| Técnica | Identificador | Descripción |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | Intentos de adivinar contraseñas |
| Remote Services: SSH | T1021.004 | Uso de SSH como servicio remoto |

Estas referencias permiten contextualizar la actividad detectada dentro del marco MITRE ATT&CK.

La asociación con estas técnicas no implica que se haya ejecutado una campaña completa de fuerza bruta ni que se haya conseguido acceso remoto.

## 8. Investigación y resolución de alertas duplicadas

Durante la primera validación se observó que algunos eventos de autenticación aparecían duplicados en los registros de alertas de Wazuh.

### 8.1. Investigación

Se comprobó que los eventos SSH se estaban recopilando desde dos fuentes diferentes:

- `journald`.
- `/var/log/auth.log`.

Al contener ambas fuentes los mismos eventos de autenticación, Wazuh podía procesar dos veces un mismo suceso.

Esto provocaba una representación duplicada de determinados eventos en el sistema de alertas.

### 8.2. Corrección aplicada

Se realizó una copia de seguridad previa del archivo de configuración:

```bash
sudo cp -a /var/ossec/etc/ossec.conf \
/var/ossec/etc/ossec.conf.pre-ssh-dedup
```

Posteriormente, se eliminó únicamente el bloque de recopilación específico de `/var/log/auth.log`, manteniendo la recopilación mediante `journald`.

Se conservó el resto de la configuración.

### 8.3. Validación posterior

Se volvió a comprobar la sintaxis XML y la configuración del Logcollector.

La validación fue correcta.

Después se realizó una nueva prueba controlada de autenticación fallida.

Los nuevos eventos aparecieron asociados a:

```text
location: journald
```

Se verificó que los nuevos registros ya no se duplicaban por la recopilación simultánea de ambas fuentes.

**Resultado:** problema de duplicidad de ingesta identificado y corregido.

## 9. Análisis de resultados

El escenario permitió comprobar el funcionamiento de diferentes componentes de una infraestructura de monitorización:

1. El servicio SSH recibió correctamente la conexión desde Kali Linux.
2. El servidor registró el intento de autenticación fallida.
3. Wazuh recopiló los eventos mediante `journald`.
4. El motor de reglas identificó los eventos y generó alertas.
5. Las reglas 5710 y 5503 permitieron distinguir distintos aspectos del proceso de autenticación.
6. Se identificó una duplicidad de ingesta causada por la monitorización simultánea de dos fuentes.
7. Se corrigió la configuración y se validó el comportamiento posterior.

### Cronología de la última validación

Los siguientes eventos corresponden a la prueba posterior a la corrección de duplicidades. Las marcas temporales están expresadas en UTC, tal como aparecen en los registros JSON.

| Hora UTC | Regla | Evento |
|---|---|---|
| 18:59:36.794 | 5710 | Usuario inexistente |
| 18:59:42.796 | 5503 | Fallo de autenticación PAM |
| 18:59:44.797 | 5710 | Contraseña fallida para usuario inexistente |

Los tres registros corresponden a eventos distintos del mismo intento de autenticación, no a tres ataques independientes.

## 10. Conclusiones

La práctica ha permitido implementar y validar un escenario básico de monitorización de autenticaciones SSH mediante Wazuh SIEM.

Se ha comprobado que el sistema es capaz de recopilar eventos de autenticación, procesarlos mediante sus reglas de detección y generar alertas que permiten iniciar una investigación.

Además, durante el desarrollo se identificó un problema real de configuración relacionado con la duplicidad de fuentes de registro. La investigación y corrección de este problema permitieron mejorar la calidad de los datos recibidos por el SIEM.

Desde el punto de vista operativo, el ejercicio ha servido para trabajar con:

- Administración básica de servicios Linux.
- Configuración y validación de Wazuh.
- Recopilación y análisis de registros.
- Detección de fallos de autenticación.
- Interpretación de alertas SIEM.
- Identificación de eventos duplicados.
- Relación de detecciones con MITRE ATT&CK.

El escenario constituye una primera práctica de detección y análisis dentro de un laboratorio Blue Team orientado al aprendizaje de tareas propias de un entorno SOC.

## 11. Limitaciones y mejoras futuras

La prueba realizada tiene un alcance limitado y sus resultados deben interpretarse teniendo en cuenta las siguientes consideraciones:

- Se ha realizado un único intento controlado de autenticación fallida.
- No se ha ejecutado una campaña de fuerza bruta con múltiples intentos.
- No se ha evaluado la detección de patrones de autenticación repetidos en un intervalo temporal.
- No se ha implementado una respuesta automática o bloqueo del origen.
- No se ha evaluado la detección de accesos SSH exitosos sospechosos.

Como posibles ampliaciones del laboratorio se plantean:

1. Simular múltiples intentos de autenticación fallida y evaluar su correlación.
2. Crear una regla personalizada de detección para patrones de intentos repetidos.
3. Investigar la actividad desde el dashboard de Wazuh.
4. Evaluar mecanismos de respuesta activa ante actividad sospechosa.
5. Ampliar la monitorización con otros escenarios, como escaneos de puertos o escalada de privilegios.

## 12. Evidencias

Las siguientes evidencias deben incorporarse al repositorio para respaldar los resultados documentados.

| Archivo | Evidencia |
|---|---|
| `01-ssh-connectivity.png` | Conectividad entre Kali y Wazuh y disponibilidad del puerto 22 |
| `02-ssh-auth-failure.png` | Intento controlado de autenticación SSH fallida |
| `03-auth-log.png` | Registros de autenticación del servidor |
| `04-wazuh-rule-5710.png` | Alerta de usuario inexistente |
| `05-wazuh-rule-5503.png` | Alerta de fallo de autenticación PAM |
| `06-deduplication-validation.png` | Validación de eventos posteriores a la corrección de duplicidades |

Las capturas deben mostrar los resultados reales del laboratorio, evitando incluir contraseñas, credenciales o información sensible.

## 13. Consideraciones éticas y de seguridad

Todas las pruebas se han realizado en un entorno virtualizado propio y controlado.

La actividad se ha limitado a sistemas del laboratorio, sin interactuar con infraestructuras de terceros ni realizar pruebas sobre servicios externos.

El propósito del ejercicio es formativo: aprender a identificar, analizar y documentar eventos de seguridad mediante herramientas utilizadas en entornos de monitorización y respuesta ante incidentes.

---

**Proyecto:** Wazuh SIEM Home Lab  
**Autor:** Portfolio personal de ciberseguridad  
**Enfoque:** Blue Team / SOC  
**Estado del escenario:** Detección y corrección de duplicidad validadas.
