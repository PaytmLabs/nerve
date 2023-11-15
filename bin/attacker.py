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
   Launch NSE rules according to config

   :param conf dict: Scan configuration variable. Used to know which rules to run.
  """

  """
    Get scan data from Redis, True param is used to erase data from db.
  """
  data = rds.get_scan_data(True)
  exclusions = rds.get_exclusions()

  if not data:
    return

  """
    Nmap doesn't support multiple scripts with different ports on one command.
    Therefore multiple commands are ran in parallel for each port of each host.
    For each host launch a new attack thread

    Launch attack for nse directory scripts
  """
  for ip, values in data.items():
    if 'ports' in values and len(values['ports']) > 0: 
      logger.info('Running NSE directory scripts: Attacking Ports: {} of asset: {}'.format(values['ports'], ip))
      scripts_names_nse = os.listdir(config.NSE_SCRIPTS_PATH)
      scripts_names = [x[:-4] for x in scripts_names_nse]

      for script in scripts_names:
        """
          Check if the target is in exclusions list, if it is, skip.
          Exclusion list can be accessed through api/exclusion api endpoint. More info on documentation view.
        """
        if script in exclusions and ip in exclusions[script]:
          logger.debug('Skipping rule {} for target {}'.format(script, ip))
          continue

        metadata = get_metadata(script, 'local')
        if not 'error' in metadata and conf['config']['allow_aggressive'] >= metadata['intensity'] and not (not conf['config']['allow_bf'] and 'brute' in metadata['categories']):
          thread = threading.Thread(target=check_rule, args=(script,  metadata, ip, values, conf, 'local'), name='nse_rule_{}'.format(script))
          thread.start()
        elif 'error' in metadata:
          logger.info("Error {} for script: {}".format(metadata['error'], script))


  """
    Launch attack for nmap scripts
  """
  for ip, values in data.items():
    if 'ports' in values and len(values['ports']) > 0: 
      logger.info('Running Nmap NSE scripts: Attacking Ports: {} of asset: {}'.format(values['ports'], ip))
      for script in config.NMAP_SCRIPTS_IN_ASSESSMENT:
        """
          Check if the target is in exclusions list, if it is, skip.
          Exclusion list can be accessed through api/exclusion api endpoint. More info on documentation view.
        """
        if script in exclusions and ip in exclusions[script]:
          logger.debug('Skipping rule {} for target {}'.format(script, ip))
          continue

        metadata = get_metadata(script, 'nmap')
        if not 'error' in metadata and conf['config']['allow_aggressive'] >= metadata['intensity'] and not (not conf['config']['allow_bf'] and 'brute' in metadata['categories']):
          thread = threading.Thread(target=check_rule, args=(script,  metadata, ip, values, conf, 'nmap'), name='nse_rule_{}'.format(script))
          thread.start()
        elif 'error' in metadata:
          logger.info("Error {} for script: {}".format(metadata['error'], script))

  
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
