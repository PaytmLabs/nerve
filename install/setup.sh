#!/bin/bash

# Nerve installation script.


# path of NERVE' systemd file
systemd_service="/lib/systemd/system/nerve.service"

# if NERVE' systemd file exists...
if [ -f $systemd_service ]; then
  # ... we get the old username/password pair...
  password=$(grep "Environment=password=" /lib/systemd/system/nerve.service)
  username=$(grep "Environment=username=" /lib/systemd/system/nerve.service)
  password=${password#"Environment=password="}
  username=${username#"Environment=username="}
else
  # ... otherwise we generate new random access credentials.
  password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 12)
  username="admin_"$(cat /dev/urandom | tr -dc '0-9' | head -c 4)
fi

# if NERVE's config.py exists...
if [ -f "config.py" ]; then
  # ... we get the old TCP port from it...
  port=$(grep WEB_PORT config.py | awk -F' = ' '{print $2}')
else
  # ... otherwise we use the default 8080/TCP.
  port=8080
fi

# we also get the current working directory...
cwd="$(pwd)"
# ... and the operating system.
os=$(grep '^ID=' /etc/*-release | cut -d'=' -f2)


# we want that this script is being executed as root.
if [ "$EUID" -ne 0 ]; then 
  echo "[!] This script must be run as root."
  exit 1
fi

# we want that this script is executed from the /opt/nerve folder.
if [ "$cwd" != "/opt/nerve" ]; then
  echo "[!] This script must be run from within the folder /opt/nerve"
  exit 1
fi

# we make sure that requirements.txt is present in the cwd folder.
if [ ! -f "requirements.txt" ]; then
  echo "[!] requirements.txt is missing. Did you unpack the files into /opt/nerve?"
  exit 1
fi

# we check if NERVE can be installed on the current operating system.
case $os in
"redhat" | "ubuntu" | "debian")
  echo "[+] This operating system ($os) is supported."
  ;;
*)
  cat <<EOF
[!] This operating system ($os) is not supported.
    Only CentOS 7.x, Ubuntu 18.x, Debian 11.x are supported.
EOF
  exit 1
  ;;
esac

# we make sure that a working Internet connection is present.
if ! ping -c 1 -W 3 google.com &> /dev/null; then
  echo "[!] You must have a working internet connection to download the dependencies."
  exit 1
fi

# this function installs required packages in a redhat-like environment
function install_redhat {
  yum install epel-release -y && \
  yum update -y && \
  yum install -y gcc && \
  yum install -y redis && \
  yum install -y python3 && \
  yum install -y python3-pip && \
  yum install -y python3-devel && \
  yum install -y python3-virtualenv && \
  yum install -y wget && \
  yum clean all
  wget https://nmap.org/dist/nmap-7.90-1.x86_64.rpm
  rpm -U nmap-*.rpm
  rm -rf nmap-*.rpm
}

# this function installs required packages in a debian environment
function install_debian {
  apt -y update && \
  apt -y install gcc redis python3 python3-pip python3-dev virtualenv \
                 libjpeg-dev libffi-dev wget nmap 
}

# this function installs required packages in an ubuntu environment
function install_ubuntu {
  apt -y update && \
  apt -y install gcc redis python3 python3-pip python3-dev virtualenv wget nmap
}

# this function configures firewalld (if present).
function configure_firewalld {
  if firewall-cmd -V &> /dev/null; then
    if ps aux | grep -v grep | grep -q firewalld; then
      echo "[+] Detected a running instance of Firewalld."
      echo -n "[+] Adding Firewalld rule to the public zone: ${port}/tcp... "
      firewall-cmd --zone=public --permanent --add-port=${port}/tcp &> /dev/null
      firewall-cmd --reload
      if [ $? != 1 ]; then echo "OK!"; else "KO"; fi      
    fi
  fi
}

# this function configures iptables (if present).
function configure_iptables {
  if iptables -V &> /dev/null; then
    echo "[+] Detected iptables."
    if ! iptables -vnL | grep -q "NERVE Console"; then
      echo -n "[+] Adding an iptables rule to allow access to NERVE's Web console... "
      iptables -I INPUT -p tcp --dport ${port} -j ACCEPT -m comment --comment "NERVE Console"
      iptables-save
      if [ $? != 1 ]; then echo "OK!"; else "KO"; fi
    fi
  fi
}

# this function configures SELinux
function configure_selinux {
  if [ -f "/sbin/setenforce" ]; then
    echo -n "[+] Setting SELinux in Permissive Mode... "
    setenforce 0
    if [ $? != 1 ]; then echo "OK!"; else "KO"; fi
    
    if [ -f /etc/sysconfig/selinux ]; then
      if grep -q enforcing /etc/sysconfig/selinux; then
        echo -n "[+] Setting SELinux in Permissive Mode... "
        sed -i "s/enforcing/permissive/g" /etc/sysconfig/selinux &> /dev/null
        if [ $? != 1 ]; then echo "OK!"; else "KO"; fi
      fi
    fi
  fi
}

# this function is a wrapper for other firewall check and setup functions.
function check_fw {
  configure_firewalld
  configure_iptables
}


# according to $os value
# - we install the right packages
# - we select the correct name for the redis service
#   and store it in the redis_service variable
echo "[+] Installing packages..."
redis_service=""

case $os in
"ubuntu")
  install_ubuntu
  redis_service="redis-server.service"
  ;;

"debian")
  install_debian
  redis_service="redis-server.service"
  ;;

"redhat")
  install_redhat
  redis_service="redis.service"
  ;;
esac

# we enable and start the redis service
echo "[+] Starting Redis..."
systemctl enable $redis_service
systemctl start $redis_service

# we create a new python3 virtual environment
echo "[+] Creating python3 virtual environment..."
rm -rf /opt/nerve/env
mkdir /opt/nerve/env
chmod 640 /opt/nerve/env
virtualenv -q /opt/nerve/env
if [ $? != 1 ]; then echo "OK!"; else "KO"; fi

# we install python3 dependencies
echo "[+] Installing python3 dependencies..."
. /opt/nerve/env/bin/activate
/opt/nerve/env/bin/pip3 install -r requirements.txt


# we create a systemd file
echo -n "[+] Setting up systemd service... "
echo "
[Unit]
Description=NERVE
After=network.target $redis_service

[Service]
Type=simple
WorkingDirectory=/opt/nerve
Environment=username=$username
Environment=password=$password
ExecStart=/bin/bash -c 'cd /opt/nerve/ && /opt/nerve/env/bin/python3 /opt/nerve/main.py'

[Install]
WantedBy=multi-user.target
" > "$systemd_service"
if [ $? != 1 ]; then echo "OK!"; else "KO"; fi
chown root:root "$systemd_service"
chmod 640 "$systemd_service"


# we enable and start NERVE
echo "[+] Starting NERVE..."
systemctl daemon-reload
systemctl enable nerve
systemctl start nerve

# we check and setup the firewall (if present)
echo "[+] Checking Firewall..."
check_fw

# we check and setup SELinux (if present)
echo "[+] Checking SELinux..."
configure_selinux

# we check if nerve is running
systemctl is-active --quiet nerve
if [ $? != 1 ]; then
  cat <<EOF

[+] Setup Complete!

[+] You may access NERVE using the following URL: http://your_ip_here:${port}.

[+] Credentials:
    - You must have valid credentials to access NERVE.

    - If this is a fresh installation, some random credentials have been generated.
      Otherwise, your old credentials have been kept.

    - NERVE stores credentials in the file $systemd_service,
      which is owned and editable by root only.

    - You can change your credentials by editing that file.
      Once done, remember to reload and restart NERVE:
        systemctl daemon-reload && systemctl restart nerve

EOF
  exit 0
else
  echo "Something went wrong, and the service could not be started."
  exit 1
fi
