## Table of Contents
* [Continuous Security](#Continuous-Security)
* [About NERVE](#)
  * [What is NERVE](#about)
  * [Deployment Recommendations](#deployment)
  * [Screenshots](#screenshots)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Installation - Docker](#docker)
  * [Installation - Bare Metal](#server)
* [Usage](#usage)
* [License](#license)

# Continuous Security
We believe security scanning should be done continuously. Not daily, weekly, monthly, or quarterly.

The benefit of running security scanning contiuously can be any of the following:
* You have a dynamic environment where infrastructure gets created every minute / hour / etc.
* You want to be the first to catch issues before anyone else
* You want the ability to respond quicker.

NERVE was created to address this problem. Commercial tools are great, but they are also heavy, not easily extendible, and cost money. 

# About
## Network Exploitation, Reconnaissance & Vulnerability Engine
NERVE is a vulnerability scanner tailored to find low-hanging fruit level vulnerabilities, in specific application configurations, network services, and unpatched services.

It is not a replacement for Qualys, Nessus, or OpenVAS. It does not do authenticated scans, and operates in black-box mode.

NERVE will do "some" CVE checks, but this is primarily coming from version fingerprinting. 


![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/2.png?raw=true)

## Deployment
The best way to deploy it, is to run it against your infrastructure from multiple regions (e.g. multiple instances of NERVE, in multiple countries), and toggle continuous mode so that you can catch short-lived vulnerabilities in dynamic environments/cloud.

We typically recommend not to whitelist the IP addresses where NERVE will be initiating the scans from, to truly test your infrastructure from an attacker standpoint.

To make NERVE fairly lightweight, there's no use of a database other than Redis.

If you want to store your vulnerabilities long term, we recommend using the Web hook feature. At the end of each scan cycle, NERVE will dispatch a JSON payload to an endpoint of your choice, and you can then store it in a database for further analysis.


![Nerve](https://github.com/PaytmLabs/nerve/blob/master/static/screenshots/arch.png?raw=true)


# Prerequisites
NERVE will install all prerequisites for you automatically (b y using `install/setup.sh` script). it comes with a Dockerfile for your convenience, or, if you prefer, you could install it on a Server (CentOS 7.x and Ubuntu 18.x were tested)

Keep in mind, NERVE requires python 3.x and libraries such as python-nmap, requests, etc. and needs root access for the initial setup.


# Installation

## Docker
### Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

### Build the Docker image
`docker build -t nerve .`

### Create a container from the image
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d -p 80:8080 nerve`

In your browser, navigate to http://ip.add.re.ss:80 and login with the credentials you specified to in the previous command.

# Server
## Navigate to /opt
`cd /opt/`

## Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

## Run Installer (requires root)
`bash install/setup.sh`

## Check NERVE is running
`systemctl status nerve`

In your browser, navigate to http://ip.add.re.ss:8080 and use the credentials printed in your terminal.

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
