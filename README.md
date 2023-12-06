# Network Exploitation, Reconnaissance & Vulnerability Apparatus with Nmap Additions (N.E.R.V.A.N.A)
[![es](https://img.shields.io/badge/lang-es-yellow.svg)](https://github.com/TomasTorresb/nervana/blob/master/README.es.md)
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/dashboard-en.png?raw=true)

# Table of Contents
* [Continuous Security](#Continuous-Security)
* [About NERVANA](#)
  * [What is NERVANA](#about-nervana)
  * [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Deployment Recommendations](#Deployment-Recommendation)
  * [Installation - Docker](#docker)
  * [Installation - Bare Metal](#server)
  * [Installation - Multi Node](#Multi-Node-Installation)
  * [Remote view of interfaces](#view-remote-interfaces)
  * [Upgrade](#upgrade)
* [Security](#security)
* [Usage](#usage)
* [License](#license)
* [Mentions](#mentions)
* [Screenshots](#screenshots)


# Continuous Security
We believe security scanning should be done continuously. Not daily, weekly, monthly, or quarterly.

The benefit of running security scanning contiuously can be any of the following:
* You have a dynamic environment where infrastructure gets created every minute / hour / etc.
* You want to be the first to catch issues before anyone else
* You want the ability to respond quicker.

NERVANA was created to address this problem. Commercial tools are great, but they are also heavy, not easily extensible, and cost money. 

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/diagram-en.png?raw=true)

# About NERVANA
NERVANA is a vulnerability scanner tailored to find low-hanging fruit level vulnerabilities, in specific application configurations, network services, and unpatched services.

Example of some of NERVANA's detection capabilities:
* Interesting Panels (Solr, Django, PHPMyAdmin, etc.)
* Subdomain takeovers
* Open Repositories
* Information Disclosures
* Abandoned / Default Web Pages
* Misconfigurations in services (Nginx, Apache, IIS, etc.)
* SSH Servers
* Open Databases
* Open Caches
* Directory Indexing
* Best Practices

It is not a replacement for Qualys, Nessus, or OpenVAS. It does not do authenticated scans, and operates in black-box mode only.

# Features
NERVANA offers the following features:
* Dashboard (With a Login interface)
* REST API (Scheduling assessments, Obtaining results, etc)
* Notifications
  * Slack
  * Email
  * Webhook
* Reports
  * TXT
  * CSV
  * HTML
  * XML
* Customizable scans
  * Configurable intrusiveness levels
  * Scan depth
  * Exclusions
  * DNS / IP Based
  * Thread Control
  * Custom Ports
  * Mode of scanning
* Network Topology Graphs
* Interface in spanish and english
* Options for adding scripts (see guide)

We put together the Graphical User Interface primarily for ease of use, but we will be putting more emphasis on detections and new signatures than creating a full blown user interface. 

# Prerequisites
NERVANA will install all the prerequisites for you automatically if you choose the Server installation (CentOS 7.x and Ubuntu 18.x were tested) (by using `install/setup.sh` script). It also comes with a Dockerfile for your convenience. 

Keep in mind, NERVANA requires root access for the initial setup on bare metal (package installation, etc).

Services and Packages required for NERVANA to run:
* Web Server (Flask)
* Redis server (binds locally)
* Nmap package (binary and Python nmap library)
* Inbound access on HTTP/S port (you can define this in config.py) 

The installation script takes care of everything for you, but if you want to install it by yourself, keep in mind these are required.

# Installation
## Deployment Recommendation
The best way to deploy it, is to run it against your infrastructure from multiple regions (e.g. multiple instances of NERVANA, in multiple countries), and toggle continuous mode so that you can catch short-lived vulnerabilities in dynamic environments/cloud.

We typically recommend not to whitelist the IP addresses where NERVANA will be initiating the scans from, to truly test your infrastructure from an attacker standpoint.

To make NERVANA fairly lightweight, there's no use of a database other than Redis.

If you want to store your vulnerabilities long term, we recommend using the Web hook feature. At the end of each scan cycle, NERVANA will dispatch a JSON payload to an endpoint of your choice, and you can then store it in a database for further analysis.

Here are the high level steps we recommend to get the most optimal results:
1. Deploy NERVANA on 1 or more servers.
2. Create a script that fetches your Cloud services (such as AWS Route53 to get the DNS, AWS EC2 to get the instance IPs, AWS RDS to get the database IPs, etc.) and maybe a static list of IP addresses if you have assets in a Datacenter.
3. Call NERVANA API (`POST /api/scan/submit`) and schedule a scan using the assets you gathered in step #2.
4. Fetch the results programmatically and act on them (SOAR, JIRA, SIEM, etc.)
5. Add your own logic (exclude certain alerts, add to database, etc.)

## Docker
### Clone the repository
`git clone git@github.com:TomasTorresB/nervana.git && cd nervana`

### Build the Docker image
`docker build -t nervana .`

### Create a container from the image
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d -p 80:8080 nervana`

In your browser, navigate to http://ip.add.re.ss:80 and login with the credentials you specified to in the previous command.

## Server
### Navigate to /opt
`cd /opt/`

### Clone the repository
`git clone git@github.com:TomasTorresB/nervana.git && cd nervana`

### Run Installer (requires root)
`bash install/setup.sh`

### Check NERVANA is running
`systemctl status nervana`

In your browser, navigate to http://ip.add.re.ss:8080 and use the credentials printed in your terminal.


# Multi Node Installation
If you want to install NERVANA in a multi-node deployment, you can follow the normal bare metal installation process, afterwards:
1. Modify the config.py file on each node
2. Change the server address of Redis `RDS_HOST` to point to a central Redis server that all NERVANA instances will report to.
3. Run `service nervana restart` or `systemctl restart nervana` to reload the configuration
4. Run `apt-get remove redis` / `yum remove redis` (Depending on the Linux Distribution) since you will no longer need each instance to report to itself.
Don't forget to allow port 3769 inbound on the Redis instance, so that the NERVANA instances can communicate with it.

## View Remote Interfaces
In order to use the tool remotely a tunnel must be setup in order to allow interactions between remote and local machines. The easiest way to achieve this is to connect both machines through SSH and have a local proxy connected to your browser. An example using firefox is listed below:
1. Establish SSH connection between local and remote machines and setup a local proxy on port 8888: : `ssh -D localhost user@nervanaIP`
2. Connect firefox to local proxy: Firefox Config -> Proxy -> Socks 5 host:localhost:8888
3. Visualiza interfaces: http://RemoteMachineIP:RemoteMachinePort


# Upgrade
If you want to upgrade your platform, the fastest way is to simply git clone and overwrite all the files while keeping key files such as configurations.

* Make a copy of `config.py` if you wish to save your configurations
* Remove `/opt/nervana` and git clone it again.
* Move `config.py` file back into `/opt/nervana`
* Restart the service using `systemctl restart nervana`.

You could set up a cron task to auto-upgrade NERVANA. There's an API endpoint to check whether you have the latest version or not that you could use for this purpose: `GET /api/update/platform`

# Security
There are a few security mechanisms implemented into NERVANA you need to be aware of.

* Content Security Policy - A response header which controls where resource scan be loaded from.
* Other Security Policies - These Response headers are enabled: Content-Type Options, X-XSS-Protection, X-Frame-Options, Referer-Policy
* Brute Force Protection - A user will get locked if more than 5 incorrect login attempts are made.
* Cookie Protection - Cookie security flags are used, such as SameSite, HttpOnly, etc.

If you identify a security vulnerability, please submit a bug to us on GitHub.

We recommend to take the following steps before and after installation
1. Set a strong password (a password will be set for you if you use the bare metal installation)
2. Protect the inbound access to the panel (Add your management IP addresses to the allow list of the local firewall)
3. Add HTTPS (you can either patch Flask directly, or use a reverse proxy like nginx)
4. Keep the instance patched

# Usage
To learn about NERVANA (GUI, API, etc.) we advise you to check out the documentation available to you via the platform.
Once you deploy it, authenticate and on the left sidebar you will find a documentation link for API and GUI usage.

## GUI Documentation
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/doc_table-en.png?raw=true)
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/auth-en.png?raw=true)

## API Documentation
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/API-en.png?raw=true)

## Add new scripts documentation
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/add_scripts_1-en.png?raw=true)
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/add_scripts_2-en.png?raw=true)
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/add_scripts_3-en.png?raw=true)

# License
It is distributed under the MIT License. See LICENSE for more information.

# Mentions
:trophy: The base tool NERVE has been mentioned in various places so far, here are a few links.
* Kitploit - https://www.kitploit.com/2020/09/nerve-network-exploitation.html
* Hakin9 - https://hakin9.org/nerve-network-exploitation-reconnaissance-vulnerability-engine/
* PentestTools - https://pentesttools.net/nerve-network-exploitation-reconnaissance-vulnerability-engine/
* SecnHack.in - https://secnhack.in/nerve-exploitation-reconnaissance-vulnerability-engine/
* 100security.com - https://www.100security.com.br/nerve

# Screenshots
## Login Screen
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/login-en.png?raw=true)
## Dashboard Screen
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/dashboard-en.png?raw=true)
## Assessment Configuration
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/assessment_configuration-en.png?raw=true)
## API Documentation
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/API-en.png?raw=true)
## Reporting
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/reports-en.png?raw=true)
## Network Map
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/topology-en.png?raw=true)
## Vulnerability page
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/vulnerabilities-en.png?raw=true)
## Log Console
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/console-en.png?raw=true)
## HTML Report
![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/HTML_report_1-en.png?raw=true)

![Nervana](https://github.com/TomasTorresB/nervana/blob/master/static/screenshots/HTML_report_2-en.png?raw=true)
