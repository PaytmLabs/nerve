import time

from core.redis   import rds
from core.logging import logger
from core.port_scanner import Scanner
from core.parser import ConfParser
from core.command_sender import CommandSender

def scanner():
  scanner = Scanner()

  logger.info('Scanner process started')

  while True:
    if not rds.is_session_active():
      time.sleep(10)
      continue

    conf = rds.get_scan_config()

    if not conf:
      time.sleep(10)
      continue

    c = ConfParser(conf)

    #try:
    #  type_ie = c.get_type_ie_config()
    #except Exception as e:
    #  logger.error('Failed to get scan type: '+ str(e))
    #  type_ie = "external"

    #if type_ie == 'internal':
    #  try:
    #    how = c.get_how_config()
    #  except Exception as e:
    #    logger.error('Failed to get how type: '+ str(e))
    #    how = ""

    #logger.info('Scanning type: ' + str(type_ie))

    hosts = rds.get_ips_to_scan(limit = c.get_cfg_scan_threads())
    logger.info("Hosts to scan: " + str(hosts))

    #if type_ie == "internal":
    #  logger.info("Sending preliminar SSH commands..")
    #  try:
    #    username_ssh = c.get_username_ssh_config()
    #    password_ssh = c.get_password_ssh_config()
    #    ip_vero = list(hosts.keys())[0]
    #    CommandSender(ip_vero, username_ssh, password_ssh, how)
    #    hosts = {'10.0.2.2': {}}
    #  except Exception as e:
    #    logger.error('Failed to execute preliminar SSH commands: '+ str(e))

    if hosts:
      conf = rds.get_scan_config()
      scan_data = scanner.scan(hosts,
                          max_ports = c.get_cfg_max_ports(),
                          custom_ports = c.get_cfg_custom_ports(),
                          interface = c.get_cfg_netinterface())

      if scan_data:
        for host, values in scan_data.items():
          real_ip = c.get_real_ip_config()
          if real_ip != '':
            host = real_ip
          if 'ports' in values and values['ports']:
            logger.info('Discovered Asset: {}'.format(host))
            logger.debug('Host: {}, Open Ports: {}'.format(host, values['ports']))
            rds.store_topology(host)
            rds.store_sca(host, values)
            rds.store_inv(host, values)
          else:
            if values['status_reason'] == 'echo-reply':
              logger.info('Discovered Asset: {}'.format(host))
              rds.store_topology(host)
