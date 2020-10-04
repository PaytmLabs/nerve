import time

from core.redis   import rds
from core.utils   import Utils
from core.logging import logger
from core.port_scanner import Scanner

def scanner():
  utils = Utils()
  scanner = Scanner()
  
  logger.info('Scanner process started')
  
  while True:
    if not rds.is_session_active():
      time.sleep(10)
      continue
    
    conf  = rds.get_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    hosts = rds.get_ips_to_scan(limit = conf['config']['scan_opts']['parallel_scan'])

    if hosts:
      conf = rds.get_scan_config()
      scan_data = scanner.scan(hosts, 
                          max_ports = conf['config']['scan_opts']['max_ports'],
                          custom_ports = conf['config']['scan_opts']['custom_ports'],
                          interface = conf['config']['scan_opts']['interface'])

      if scan_data:
        for host, values in scan_data.items():
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