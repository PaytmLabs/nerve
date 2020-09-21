## Table of Contents

* [About NERVE](#)
  * [What is NERVE](#about)
  * [Screenshots](#screenshots)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Installation - Docker](#docker)
  * [Installation - Bare Metal](#server)
* [Usage](#usage)
* [License](#license)

# About
## Network Exploitation, Reconnaissance & Vulnerability Engine
NERVE is a vulnerability scanner tailored to find low-hanging fruit level vulnerabilities, in specific application configurations, network services, and unpatched services.

The best way to deploy it, is to run it against your infrastructure in multiple regions, and toggle continuous mode.

![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/2.png?raw=true)


![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/arch.png?raw=true)

# Prerequisites
NERVE will install all prerequisites for you automatically. it comes with a Dockerfile, or, if you prefer, you could install it on a Server (CentOS 7.x and Ubuntu 18.x were tested) using the automated installation (Below)

Keep in mind, NERVE requires python 3.x and libraries such as python-nmap, requests, etc.


# Installation

## Docker
### Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

### Build the Docker image
`docker build -t nerve .`

### Create a container from the image
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d -p 80:8080 nerve`

Navigate in your browser to http://ip.add.re.ss:80 and login with the credentials you specified to in the previous command.

# Server
## Navigate to /opt
`cd /opt/`

## Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

## Run Installer (requires root)
`bash install/setup.sh`

## Check NERVE is running
`systemctl status nerve`

Navigate in your browser to http://ip.add.re.ss:8080 and use the credentials printed in your terminal.

# License
It is distributed under the MIT License. See LICENSE for more information.

# Screenshots
## Login Screen
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/1.png?raw=true)
## Dashboard Screen
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/2.png?raw=true)
## Assessment Configuration
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/3.png?raw=true)
## API Documentation
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/4.png?raw=true)
## Reporting
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/5.png?raw=true)
## Network Map
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/6.png?raw=true)
## Vulnerability page
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/7.png?raw=true)
## Log Console
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/8.png?raw=true)
## HTML Report
![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/9.png?raw=true)
