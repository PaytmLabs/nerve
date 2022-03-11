#!/bin/bash
systemd_service="/lib/systemd/system/nerve.service"
cwd="$(pwd)"
password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${1:-12} | head -n 1)

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root."
  exit 1
fi

if [ "$cwd" != "/opt/nerve" ]; then
  echo "please run this script from within /opt/nerve folder."
  exit 1
fi

if [ ! -f "requirements.txt" ]; then
  echo "requirements.txt is missing, did you unpack the files into /opt/nerve?"
  exit 1
fi

os=$(grep '^ID=' /etc/*-release | cut -d'=' -f2)
case $os in
"redhat" | "ubuntu" | "debian")
  echo "$os is supported."
  ;;
*)
  echo "$os is not supported. Only CentOS 7.x, Ubuntu 18.x, Debian 11.x are supported."
  exit 1
  ;;
esac

if ! ping -c 1 -W 3 google.com &> /dev/null; then
  echo "You must have a working internet connection to download the dependencies."
  exit 1
fi


function install_redhat {
  yum install epel-release -y && \
  yum update -y && \
  yum install -y gcc && \
  yum install -y redis && \
  yum install -y python3 && \
  yum install -y python3-pip && \
  yum install -y python3-devel && \
  yum install -y wget && \
  yum clean all
  wget https://nmap.org/dist/nmap-7.90-1.x86_64.rpm
  rpm -U nmap-*.rpm
  rm -rf nmap-*.rpm
}

function install_debian {
  apt -y update && \
  apt -y install gcc redis python3 python3-pip python3-dev \
                 libjpeg-dev libffi-dev wget nmap 
}

function install_ubuntu {
  apt -y update && \
  apt -y install gcc redis python3 python3-pip python3-dev wget nmap
}

function configure_firewalld {
  if firewall-cmd -V &> /dev/null; then
    echo "Checking Firewall settings..."
    if ps aux | grep -v grep | grep -q firewalld; then
      if [ -f "config.py" ]; then
      port=$(grep WEB_PORT config.py | awk -F' = ' '{print $2}')
      echo "Adding Firewalld rule to the public zone: 8080/tcp"
      firewall-cmd --zone=public --permanent --add-port=${port}/tcp &> /dev/null
      firewall-cmd --reload
      fi
    fi
  fi
}

function configure_iptables {
  if iptables -V &> /dev/null; then
    if ! iptables -vnL | grep -q "NERVE Console"; then
      iptables -I INPUT -p tcp --dport 8080 -j ACCEPT -m comment --comment "NERVE Console"
      iptables-save
    fi
  fi
}

function configure_selinux {
  if [ -f "/sbin/setenforce" ]; then
    echo "Setting SELinux in Permissive Mode..."
    setenforce 0
    if [ -f /etc/sysconfig/selinux ]; then
      if grep -q enforcing /etc/sysconfig/selinux; then
        sed -i s'/enforcing/permissive/'g /etc/sysconfig/selinux &> /dev/null
      fi
    fi
  fi
}

function check_fw {
  configure_firewalld
  configure_iptables
}

if [ ! -f "$systemd_service" ]; then
  echo "Setting up systemd service"
  echo "
[Unit]
Description=NERVE

[Service]
Type=simple
ExecStart=/bin/bash -c 'cd /opt/nerve/ && /usr/bin/python3 /opt/nerve/main.py'

[Install]
WantedBy=multi-user.target
" >> "$systemd_service"
  chmod 644 "$systemd_service"
fi


redis_service=""
echo "Installing packages..."

case $os in
"ubuntu")
  install_ubuntu
  redis_service="redis-server"
  ;;

"debian")
  install_debian
  redis_service="redis-server.service"
  ;;

"redhat")
  install_redhat
  redis_service="redis"
  ;;
esac

echo "Starting Redis..."
systemctl enable $redis_service
systemctl start $redis_service

echo "Installing python3 dependencies..."
pip3 install -r requirements.txt

echo "Generating password"
if [ -f "config.py" ]; then
  sed -ine s/^WEB_PASSW\ =\ .*/WEB_PASSW\ =\ \'$password\'/ "config.py"
fi

echo "Starting NERVE..."
systemctl enable nerve
systemctl start nerve

echo "Checking Firewall..."
check_fw

echo "Checking SELinux..."
configure_selinux

systemctl is-active --quiet nerve
if [ $? != 1 ]; then
  echo 
  echo
  echo "Setup Complete!"
  echo "You may access via the following URL: http://your_ip_here:8080 with the credentials as defined in config.py"
  echo "Username: admin"
  echo "Password: $password"
  echo
  exit 0
else
  echo "Something went wrong, and the service could not be started."
  exit 1
fi
