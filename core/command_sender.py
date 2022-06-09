import requests
import nmap
import config
import pexpect
import time
import os

from core.utils   import Utils
from core.triage  import Triage
from core.logging import logger
from db import db_ports
from paramiko import SSHClient
from paramiko import AutoAddPolicy


class CommandSender():
  def __init__(self, host, username, password, how):

    if how == 'automatic':
      logger.info("Automatic phase before, launching prelimary commands before tunnel creation..")
      # Connect
      client = SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(AutoAddPolicy())

      logger.info("HOST: " + str(host))
      logger.info("USERNAME: " + str(username))
      logger.info("PASSWORD: " + str(password))

      client.connect(host, 22, username, password)

      # Run a set of commands
      list = ['sed "s/^[#]\{0,1\}PermitTunnel\(.*\)/PermitTunnel point-to-point/g" /etc/ssh/sshd_config -i', 'systemctl restart sshd', 'ip tuntap add tun0 mode tun', 'ip addr add 10.0.2.2/30 dev tun0', 'ip link set dev tun0 up', 'sysctl net.ipv4.ip_forward=1', 'sysctl net.ipv4.conf.all.route_localnet=1', 'iptables -t nat -I PREROUTING -i tun0 -j DNAT --to 127.0.0.1']

      for x in range(len(list)):
        logger.info("Command to execute: " + list[x]);
        stdin, stdout, stderr = client.exec_command(list[x])
        logger.info("STDOUT: " + str(stdout.read().decode("utf8")));
        logger.info("STDERR: " + str(stderr.read().decode("utf8")));
        logger.info("RETURN CODE: " + str(stdout.channel.recv_exit_status()));

      stdin.close()
      stdout.close()
      stderr.close()
      client.close()

    else:
      logger.info("Manual phase before, creating tunnel directly..")

    options = '-f -w0:0 -q -oStrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -oPubkeyAuthentication=no'
    ssh_cmd = 'ssh %s %s@%s true' % (options, username, host)
    logger.info("SSH tunnel command: " + ssh_cmd)
    child = pexpect.spawn(ssh_cmd, timeout=3600)
    logger.info("Waiting for password prompt..")
    child.expect(['[pP]assword: '])
    logger.info("Insert password..")
    child.sendline(password)
    time.sleep(3)

    check_ssh_tunnel = os.popen("ps xa | grep ssh | grep w | grep -v grep | grep " + host).read()
    logger.info("Tunnel: " + str(check_ssh_tunnel))

    if check_ssh_tunnel == '':
      raise Exception("Tunnel down")
