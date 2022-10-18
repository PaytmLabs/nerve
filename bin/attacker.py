import time
import threading

from core.manager     import rule_manager
from core.parser      import ConfParser
from core.logging     import logger
from core.redis       import rds
from core.nse_scripts import check_rule, get_metadata

import os
import sys
import pip
# Dotenv no quedo instalado en el path de las otras librerías, por lo que hay que añadir el path. En al instalación original no debería ocurrir este problema.
sys.path.append('/home/ubuntu/.local/lib/python3.6/site-packages')
from dotenv import load_dotenv

load_dotenv()

def run_python_rules(conf):
  """
   Launch python rules according to config

   :param conf dict: Scan configuration variable. Used to know which rules to run.
  """

  data = rds.get_scan_data()
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
        logger.info('Attacking Asset: {} on port: {}'.format(ip, port))
        for rule in rules.values():
          """
            Check if the target is in exclusions list, if it is, skip.
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

def run_NSE_rules(conf):
  """
   Launch NSE rules according to config (??)
  """
  # Redis data
  data = rds.get_scan_data()
  #exclusions = rds.get_exclusions() # Not implemented for nmap yet
  
  # HARD CODED FOR NOW, SHOULD USE CONF IN THE FUTURE? 
  scripts_names = ['ftp-brute','ftp-steal']
  scripts_args = "brute.credfile={},user=ftp_user,pass=ftp_user,dir=files".format(os.environ['credfile_path'])
  #logger.debug('Scripts to be executed: {}'.format(scripts_path))
  #logger.debug('Scripts args: {}'.format(scripts_args))

  # Nmap doesn't support multiple scripts with different ports on one command.
  # Therefore multiple commands are ran in parallel for each port of each host.
  # For each host launch a new attack thread
  for ip, values in data.items():
    if 'ports' in values and len(values['ports']) > 0:  
      logger.info('Attacking Ports: {} of asset: {}'.format(values['ports'], ip))

      # Filter scripts with higher intensity
      for script in scripts_names:
        metadata = get_metadata(script)
        logger.debug('Metadata: ' + str(metadata))

        logger.debug('Config intensity: ' + str(conf['config']['allow_aggressive']))
        logger.debug('Rule intensity: ' + str(metadata['intensity']))
        if conf['config']['allow_aggressive'] >= metadata['intensity']:
         
          # Start new thread for each NSE script
          thread = threading.Thread(target=check_rule, args=(script, scripts_args, metadata, ip, values, conf))
          thread.start()


def attacker():
  """
   Daemon, always running. Launches scans.
  """

  count = 0
  logger.info('Attacker process started')
  
  while True:
    conf = rds.get_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    #run_python_rules(conf)
    run_NSE_rules(conf)
    count += 1
      
    if count == conf['config']['scan_opts']['parallel_attack']:
      time.sleep(30)
      count = 0
    
      if threading.active_count() > 50:
        logger.debug('Sleeping for 30 seconds to control threads (Threads: {})'.format(threading.active_count()))  
        time.sleep(30)
    
