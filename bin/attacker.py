import time
import threading
import config
import datetime

from core.manager     import rule_manager
from core.parser      import ConfParser
from core.logging     import logger
from core.redis       import rds
from core.nse_scripts import check_rule, get_metadata

import os
import pip

def run_python_rules(conf):
  """
   Launch python rules according to config

   :param conf dict: Scan configuration variable. Used to know which rules to run.
  """

  data = rds.get_scan_data(False)
  exclusions = rds.get_exclusions()

  if not data:
    return

  for ip, values in data.items():
    """
     Get list of all rules classes.
    """
    rules = rule_manager(role='attacker')
    if 'ports' in values and len(values['ports']) > 0:  
      for port in values['ports']:
        logger.info('Python scripts: Attacking Asset: {} on port: {}'.format(ip, port))
        for rule in rules.values():
          """
            Check if the target is in exclusions list, if it is, skip.
            Exclusion list can be accessed through api/exclusion api endpoint. More info on documentation view.
          """
          if rule.rule in exclusions and ip in exclusions[rule.rule]:
            logger.debug('Skipping rule {} for target {}'.format(rule.rule, ip))
            continue

          """
            Only run rules that are in the allowed_aggressive config level.
          """
          if conf['config']['allow_aggressive'] >= rule.intensity:
            """
              Start new thread with running rule script
            """
            thread = threading.Thread(target=rule.check_rule, args=(ip, port, values, conf))
            thread.start()


def run_nse_rules(conf):
  """
   Launch NSE rules according to config (??)
  """

  # Get scan data from Redis
  data = rds.get_scan_data(True)

  if not data:
    return

  scripts_names = ['ftp-steal'] 

  # Nmap doesn't support multiple scripts with different ports on one command.
  # Therefore multiple commands are ran in parallel for each port of each host.
  # For each host launch a new attack thread
  for ip, values in data.items():
    if 'ports' in values and len(values['ports']) > 0: 
      logger.info('Base NSE scripts: Attacking Ports: {} of asset: {}'.format(values['ports'], ip))
      for script in scripts_names:
        metadata = get_metadata(script)

        if not 'error' in metadata and conf['config']['allow_aggressive'] >= metadata['intensity']:
         
          # Start new thread for each NSE script
          thread = threading.Thread(target=check_rule, args=(script,  metadata, ip, values, conf), name='nse_rule_{}'.format(script))
          thread.start()

  # Launch attack for added scripts
  for ip, values in data.items():
    if 'ports' in values and len(values['ports']) > 0: 
      logger.info('Extra NSE scripts: Attacking Ports: {} of asset: {}'.format(values['ports'], ip))
      for script in config.NSE_SCRIPT_DIRECT_PATH:
        logger.debug("SCRIPT {}".format(script))
        metadata = get_metadata(script)

        if not 'error' in metadata and conf['config']['allow_aggressive'] >= metadata['intensity']:
          logger.debug("Comienza thread para {}".format(script)) 
          # Start new thread for each NSE script
          thread = threading.Thread(target=check_rule, args=(script,  metadata, ip, values, conf), name='nse_rule_{}'.format(script))
          thread.start()
        else:
          logger.debug("FALLO :C º script={} metadata={} ip={} values={} conf={}".format(script, metadata,ip,values,conf))

  
def attacker():
  """
   Daemon, always running. Launches scans.
  """

  count = 0
  logger.info('Attacker process started')
  
  while True:
    conf = rds.get_next_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    c = ConfParser(conf)

    if c.get_cfg_schedule() > datetime.datetime.now():
      time.sleep(10)
      continue

    run_python_rules(conf)
    run_nse_rules(conf)
    count += 1
      
    if count == conf['config']['scan_opts']['parallel_attack']:
      time.sleep(30)
      count = 0
    
      if threading.active_count() > 50:
        logger.debug('Sleeping for 30 seconds to control threads (Threads: {})'.format(threading.active_count()))  
        time.sleep(30)
    
      time.sleep(10)
      continue
