import threading

from core.parser   import ConfParser
from core.utils    import Utils
from core.logging  import logger
from core.redis    import rds

from flask_babel    import _

class Register:
  def __init__(self):
    self.rds = rds
    self.utils = Utils()
  
  def scan(self, scan):
    state = rds.get_session_state()
    if state is not None and state == 'running':
      return (False, 429, _('There is already a scan in progress!'))

    cfg = ConfParser(scan)
    
    logger.info('Storing the new configuration')
    self.rds.store_config(scan)
    
    networks = cfg.get_cfg_networks()
    domains = cfg.get_cfg_domains()
    
    if networks:
      logger.info('Scheduling network(s): {}'.format(', '.join(networks)))
    
    if domains:
      logger.info('Scheduling domains(s): {}'.format(', '.join(domains)))
    
    return (True, 200, _('Registered a new scan successfully!'))
