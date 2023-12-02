# Network Exploitation, Reconnaissance & Vulnerability Apparatus with Nmap Additions (N.E.R.V.A.N.A)
[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/TomasTorresB/nervana/blob/master/README.md)
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/dashboard-es.png?raw=true)

# Tabla de Contenidos
* [Seguridad Continua](#seguridad-continua)
* [Sobre Nervana](#)
  * [Que es Nervana](#sobre-nervana)
  * [Funcionalidades herramienta](#funcionalidades-herramienta)
* [Prerequisitos](#prerequisitos)
* [Instalación](#instalación)
  * [Recomendaciones Despliegue de la Herramienta](#recomendaciones-despliegue-de-la-herramienta)
  * [Instalación - Docker](#docker)
  * [Instalación - Bare Metal](#instalación-server)
  * [Instalación - Multi Nodo](#instalación-multi-nodo)
  * [Visualización Remota](#visualización-de-interfaces-remotas)
  * [Upgrade](#upgrade)
* [Seguridad](#seguridad)
* [Uso](#uso)
* [Licencia](#licencia)
* [Menciones](#menciones)
* [Screenshots](#screenshots)

# Seguridad Continua
Nosotros creemos que la seguridad de escaneos debe ser realizada continuamente. No diaria, semanal, mensual o trimestral.

Los beneficios de utilizar este método de escaneo son los siguientes:
* La existencia de un ambiente dinámico donde infraestructura es creada cada minuto / hora / etc.
* Es posible encontrar problemas antes que cualquier otra persona.
* Permite responder más rápidamente a incidentes.

Nervana fue creada con esta problematica en mente. Las herramientas comerciales son buenas pero también pesadas, difíciles de extender y cuestan dinero.

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/diagram-en.png?raw=true)

# Sobre Nervana
Nervana es un escáner de vulnerabilidades diseñado para encontrar vulnerabilidades del estilo 'low-hanging-fruit' en configuraciones específicas de aplicaciones, redes y servicios sin parchear.

A continuación se mencionan algunas de las capacidades de detección de Nervana:
* Paneles Interesantes(Solr, Django, PHPMyAdmin, etc.)
* Toma de control de Subdominios
* Repositorios Abiertos
* Divulgación de Información
* Páginas web por Defecto o Abandonadas.
* Servicios mal Configurados (Nginx, Apache, IIS, etc.)
* Servidores SSH
* Abrir Bases de Datos
* Abrir Caches
* Indexación de Directorios
* Mejores Praćticas

# Funcionalidades herramienta
NERVANA ofrece las siguientes funcionalidades:
* Dashboard (Con interfaz de logeo)
* REST API (Para agendar escaneos, obtener resultados, etc)
* Notificaciones
  * Slack
  * Email
  * Webhook
* Reportes
  * TXT
  * CSV
  * HTML
  * XML
* Escaneos personalizados
  * Configurar niveles de intrusividad
  * Profundidad del escaneo
  * Exclusiones
  * Basadas en DNS / IP 
  * Control de threads
  * Puertos personalizados
  * Modos de escaneo
* Gráficos de topología de la red
* Interfaz en Español e Inglés
* Opciones para agregar nuevos scripts (Ver guía)

Además presenta una interfaz gráfica para facilitar el uso de la herramienta, pero el enfásis del trabajo se centra en la detección de vulnerabildidaes y nuevas firmas más que en la creación de una interfaz de usuario completa.

# Prerequisitos
Nervana instalará todos los prerequisitos automaticamente al escoger la opción de instalación en el servidor(Testeado en Ubuntu 18.x)(al correr el script `install/setup.sh` ). El proyecto original también viene con un Dockerfile para su conviencia.

Es importante mencionar que Nervana requiere de acceso *root* para la configuración inicial en la máquina(instalación de paquetes, etc).

Servicios y Paquetes requeridos para que Nervana pueda correr:
* Servidor Web (Flask)
* Servidor Redis (local)
* Paquete Nmap (Binario y librería de Python llamda `python-nmap` )
* Acceso a conexiones entrantes en el puerto HTTP/S (esto se puede definir en config.py)

El *script* de instalación se encarga de todo, pero si se opta por una instalación manual es necesario considerar estos requerimientos.

# Instalación
## Recomendaciones Despliegue de la Herramienta
La mejor forma de desplegar Nervana, es correr la herramienta contra la infraestructura que se quiere atacar desde múltiples regiones(e.g. múltiples instancias de Nervana en múltiples países) y configurar las herramientas en modo de escaneo continuo para encontrar vulnerabilidades de corta duracióin en ambientes dinámicos o cloud.

No se recomienda dar privilegios especiales a las direcciones IP donde ataca Nervana, para realmente probar la infraestrcutura desde el punto de vista de un atacante.

Para hacer Nervana bastante ligero, no se utilizan otras bases de datos además de Redis.

Si se quieren almacenar las vulnerabilidades encontradas a largo plazo, se recomineda utiliza la funcionalidad *Webhook* al finalizar cada ciclo de escaneo. De este modo, Nervana enviará un JSON *payload* a un *endpoint* de elección, en donde se puede almacenar esta información en una base de datos para un analísis posterior.

A continuación se mencionan los pasos de alto nivel que se recomiendan para obtener resultados óptimos:
1. Desplegar Nervana en 1 o más servidores
2. Crear un *script* que extraiga informacón de servicios Cloud(como WS Route53 para obtener el DNS, AWS ECi2 para obtener las direcciones IPs de la instancia, AWS RDS para obtener las bases de datos de IPs, etc.)
3. Llamar a la API de Nervana(`POST /api/scan/submit`) y agendar un escaneo utilizando los activos informáticos extraídos en el paso # 2.
4. Automatizar la obtención de resultados y actuar sobre ellos (SOAR, JIRA, SIEM, etc).
5. Agregar logica propia (excluir ciertas alertas, agregar a una base de datos, etc).

## Docker
### Clonar el repositorio
`git clone git@github.com:TomasTorresB/nervana.git && cd nervana`

### Construir la imagen de Docker
`docker build -t nervana .`

### Crear un contenedor para la imagen
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d -p 80:8080 nervana`

En el browser navegar a http://ip.add.re.ss:80 e iniciar sesión con las credenciales específicadas en el comando previo.

## Instalación Server
### Navegar a /opt
`cd /opt/`

### Clonar el repositorio	
`git clone git@github.com:TomasTorresB/nervana.git && cd nervana`

### Correr el instalador (requiere root)
`bash install/setup.sh`

### Chequear que NERVANA corra
`systemctl status nervana`

En el navegador web, visitar http://ip.add.re.ss:8080 y utilizar las credenciales imprimidas en el terminal.


## Instalación Multi Nodo
En el caso que se prefiera una instalación multi-nodo de la herramienta, se pueden seguir las intrucciones básicas de instlación y luego:
1. Modificar el archivo config.py en cada nodo
2. Cambiar el "server address" de Redis a `RDS_HOST` para que apunte a servidor central de Redis al que todas las instacias de Nervana reportarán.
3. Correr `service nervana restart` o `systemctl restart nervana` para recargar las configuraciones
4. Correr `apt-get remove redis` / `yum remove redis`(Dependiendo de la distribución de Linux) dado que no sera necesario una instancia para cada nodo.
No olvidar permitir al puerto 3769 recibir conexiones entrantes en la instancia de Redis, de modo que las instancias de Nervana puedan comunicarse con la base de datos.

## Visualización de interfaces remotas
Para manejar remotamente la interfaces de la herramienta es necesario configurar un tunel que permita interactuar con las interfaces remotamente. La forma más simple de lograr esto es mediante una conexión SSH y un servidor *proxy* local conectado al navegador web de preferencia. A modo de ejemplo se listan los los pasos utilizando el navegador web firefox:
1. Establecer conexión SSH con la máquina en donde se aloja la herramienta y levantar servidor *proxy* local en puerto 8888: `ssh -D localhost:8888 usuario@nervanaIP`
2. Configurar firefox con el servidor *proxy*:  Configuraciones Firefox -> Proxy -> Socks 5 host:localhost:8888
3. Visualizar interfaz: http://IPMaquinaRemota:PuertoMaquinaRemota


## Upgrade
En el caso de querer mejorar la plataforma, lo más fácil es simplemente clonar nuevamente el repositorio nuevamente el repositorio y sobreescribir todos los archivos manteniendo los archivos claves como configuraciones. Los pasos se listan a continuación:
* Hacer una copia del archivo `config.py` en el caso de querer guardar las configuraciones.
* Borrar  `/opt/nervana` y nuevamente hacer git clone.
* Mover el archivo `config.py`devuelta a `/opt/nervana`.
* Reanudar el servicio utilizando `systemctl restart nervana`.

Se puede configurar un *cron task* para realizar mejorar automáticas de Nervana. Hay un API *endpoint* que permite checkear las últimas versiones disponibles que se puede utilizadar para estos propositos: `GET /api/update/platform`

# Seguridad
Hay algunos mecanismos de seguridad implementados en Nervana que son importantes de considerar.

* *Content Security Policy* - Corresponde a un encabezado de las respuestas que permite controlar desde donde los recursos de los escaneos son cargados.
* Otras Políticas de Seguridad - Estos encabezados de respuestas se encuentran habilitados: *Content-Type Options, X-XSS-Protection, X-Frame-Options, Referer-Policy*.
* Protección de Fuerza Bruta - Un usuario será bloqueado al fallar 5 intentos de inicio de sesión.
* Protección de *cookies* - *Flags* de seguridad de *cookies* son utilizadas, como SameSite, HttpOnly, etc.

En el caso de identificar una vulnerabilidad en el escaneo, por favor informar el bug el GitHub.

Se recomiendan los siguientes pasos antes y después de instalar la herramienta:
1. Setear una fuerte contraseña (una contraseña por defecto será configurada en el caso de seguir las intrucciones de instalación).
2. Proteger el panel de control de conexiones entrantes (Agregar la IP de manejo a la lista de direcciones permitidas del firewall local).
3. Agregar HTTPS (se puede parchar Flask directamente, o usar un *proxy* inverso como nginx).
4. Mantener la instancia con los parches al día.

# Uso
Para aprender más sobre NERVANA(GUI,API, Agregar nuevos scripts, etc) se recomienda leer al documentación disponible vía la plataforma. Al desplegar la aplicación, autenticarse y luego en la barra lateral izquierda revisar la documentación.

## Documentación GUI
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/doc_table-es.png?raw=true)

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/auth-es.png?raw=true)

## Documentación API
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/API_table-es.png?raw=true)

## Documentación agregar nuevos scripts 
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/add_scripts_1-es.png?raw=true)

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/add_scripts_2-es.png?raw=true)

# Licencia
Se distribuye bajo la Licencia MIT. Ver LICENSE para más información.

# Menciones
:trophy: La herramienta base NERVE ha sido mencionada en varios lugares hasta ahora, a continuación se mencionan algunos links:
* Kitploit - https://www.kitploit.com/2020/09/nerve-network-exploitation.html
* Hakin9 - https://hakin9.org/nerve-network-exploitation-reconnaissance-vulnerability-engine/
* PentestTools - https://pentesttools.net/nerve-network-exploitation-reconnaissance-vulnerability-engine/
* SecnHack.in - https://secnhack.in/nerve-exploitation-reconnaissance-vulnerability-engine/
* 100security.com - https://www.100security.com.br/nerve

# Capturas de Pantalla
## Pantalla de Logeo
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/login-es.png?raw=true)
## Dashboard
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/dashboard-es.png?raw=true)
## Configuración Evaluación
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/assessment_configuration-es.png?raw=true)
## Documentación API
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/API-es.png?raw=true)
## Reportes
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/reports-es.png?raw=true)
## Mapa de la Red
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/topology-es.png?raw=true)
## Página de Vulnerabilidades
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/vulnerabilities-es.png?raw=true)
## Consola de Logeo
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/console-es.png?raw=true)
## Reporte HTML
![Nervana](https://github.com/TomasTorresB/nevana/blob/master/static/screenshots/HTML_report_1-es.png?raw=true)

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/HTML_report_2-es.png?raw=true)
