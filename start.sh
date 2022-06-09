#!/bin/bash

echo "Create TUN for internal inspections"
mkdir -p /dev/net
mknod /dev/net/tun c 10 200
chmod 600 /dev/net/tun
ip tuntap add tun0 mode tun
ip addr add 10.0.2.1/30 dev tun0
ip link set dev tun0 up

echo "Start redis.."
nohup redis-server --bind 127.0.0.1 & &> /dev/null

echo "Start NERVE.."
/usr/bin/python3 main.py

echo "Exited.."
