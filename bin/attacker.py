import time
import threading

from core.manager   import rule_manager
from core.parser    import ConfParser
from core.logging   import logger
from core.redis     import rds

import nmap

def run_python_rules(conf):
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

def run_lua_rules():
  # Redis data
  data = rds.get_scan_data()
  #exclusions = rds.get_exclusions() # Not implemented for nmap yet
  nm = nmap.PortScanner()

  # Nmap args
  path_to_scripts = '/usr/share/nmap/scripts/'
  name_of_scripts = ['ftp-steal.nse'] #['ftp-force.nse']
  ports = ''
  scripts = "--script " # Por ahora se esta testeando solo 1 script con sus argumentos, a futuro verificar que esto funcione con multiples
  script_args = "--script-args user=ftp_user,pass=ftp_user,dir=files"
  for n in name_of_scripts:
    scripts += path_to_scripts + n + ','

  # IPs and Ports
  # Falta añadir threading
  for ip, values in data.items():
    logger.info('Values: {}, ports: {}'.format(values, values['ports']))
    if 'ports' in values and len(values['ports']) > 0:  
      ports = '-p {}'.format(','.join([str(p) for p in values['ports']]))
      # Execute script
      logger.info('Ports:{}, Scripts: {}, Scripts args: {}, Ip: {}'.format(ports, scripts[:-1], script_args, ip))
      test = nm.scan(ip, arguments='{} {} {}'.format(ports, scripts[:-1], script_args))
      logger.info(nm.command_line())
      test_scan_finished = nm.all_hosts()
      test_scan_finished_len = len(test_scan_finished)
      # Check if the host has not been  switched off in the middle of scan
      if test_scan_finished_len == 0:
        logger.info(test)
        logger.info('Error during scan')
      else:
        output_scan = nm._scan_result['scan'][ip]
        logger.info(output_scan)
        logger.info(output_scan.keys())
        logger.info('-----')
        #check if script worked
        scan_results_test = "script"
        for p in values['ports']:
          # Que pasa si es UDP o alguna otra cosa
          logger.info('Port: ' + str(p))
          if scan_results_test in output_scan['tcp'][p]:
            logger.info('Sucessful scan')
            logger.info(output_scan['tcp'][p]['script'])
            logger.info('End')
          else:
            logger.info('Error while executing script')

def attacker():
  count = 0
  logger.info('Attacker process started')
  
  while True:
    conf = rds.get_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    #run_python_rules(conf)
    run_lua_rules()
    count += 1
      
    if count == conf['config']['scan_opts']['parallel_attack']:
      time.sleep(30)
      count = 0
    
      if threading.active_count() > 50:
        logger.debug('Sleeping for 30 seconds to control threads (Threads: {})'.format(threading.active_count()))  
        time.sleep(30)
    
