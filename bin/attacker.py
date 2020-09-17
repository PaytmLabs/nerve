import time
import threading

from core.manager   import rule_manager
from core.parser    import ConfParser
from core.logging   import logger
from core.redis     import rds

def run_rules(conf):
  data = rds.get_scan_data()
  
  if not data:
    return

  for ip, values in data.items():
    rules = rule_manager(role='attacker')
    if 'ports' in values and len(values['ports']) > 0:  
      for port in values['ports']:
        logger.info('Attacking Asset: {} on port: {}'.format(ip, port))
        for rule in rules.values():
          if conf['config']['allow_aggressive'] >= rule.intensity:
            thread = threading.Thread(target=rule.check_rule, args=(ip, port, values, conf))
            thread.name = 'rule_{}_{}_{}'.format(rule.rule, ip, port)
            thread.start()

def attacker():
  count = 0
  logger.info('Attacker process started')
  
  while True:
    conf = rds.get_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    run_rules(conf)
    count += 1
      
    if count == conf['config']['scan_opts']['parallel_attack']:
      time.sleep(30)
      count = 0
    
      if threading.active_count() > 50:
        logger.debug('Sleeping for 30 seconds to control threads (Threads: {})'.format(threading.active_count()))  
        time.sleep(30)
    