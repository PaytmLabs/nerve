# About
NERVE is a vulnerability scanner tailored to find vulnerabilities in specific application configurations, network services, and unpatched services.

# Installation using Docker
## Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

## Build the Docker image
`docker build -t nerve .`

## Create a container from the image
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d -p 80:8080 nerve`

Navigate in your browser to http://ip.add.re.ss:80

# Installation on bare bone server (CentOS 7.x and Ubuntu 18.x)
## Navigate to /opt
`cd /opt/`

## Clone the repository
`git clone git@github.com:PaytmLabs/nerve.git && cd nerve`

## Run Installer (requires root)
`bash install/setup.sh`

## Check NERVE is running
`systemctl status nerve`

Navigate in your browser to http://ip.add.re.ss:8080

# Screenshots
## Login Screen
![Login](https://github.com/PaytmLabs/nerve/blob/master/1.png?raw=true)
