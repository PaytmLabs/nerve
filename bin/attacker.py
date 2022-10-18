import time
import threading

from core.manager   import rule_manager
from core.parser    import ConfParser
from core.logging   import logger
from core.redis     import rds
from core.parser    import ScanParser

import nmap
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

   Parameters: 
     conf (dict): Scan configuration variable. Used to know which rules to run.
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

# [FALTA INCORPORAR CONFIG]
def run_NSE_rules():
  """
   Launch lua rules according to config
  """
  # Redis data
  data = rds.get_scan_data()
  #exclusions = rds.get_exclusions() # Not implemented for nmap yet
  nm = nmap.PortScanner()
  
  # Nmap args
  path_to_scripts = os.environ['Nmap_scripts_path']
  scripts_names = ['ftp-brute.nse','ftp-steal.nse']
  #scripts_args = "--script-args user=ftp_user,pass=ftp_user,dir=files"
  scripts_args = "--script-args brute.credfile=/home/ubuntu/Documents/creds.txt,user=ftp_user,pass=ftp_user,dir=files"

  #logger.debug('Scripts to be executed: {}'.format(scripts_path))
  #logger.debug('Scripts args: {}'.format(scripts_args))

  # Nmap doesn't support multiple ports with different ports on one command.
  # Therefore multiple commands are ran in parallel for each port of each host.
  # Note: It is not possible to map a script to a specific port but not the other scripts to that port as well. Thus all scripts are executed for each port,ip combination.
  # For each host launch a new attack thread
  for ip, values in data.items():

    if 'ports' in values and len(values['ports']) > 0:  
      logger.info('Attacking Ports: {} of asset: {}'.format(values['ports'], ip))

      # Start new thread with NSE script
      thread = threading.Thread(target=NSE_rules, args=(nm, ip, values, scripts_names, path_to_scripts, scripts_args))
      thread.start()


def NSE_rules(nm, ip, values, scripts_names, path_to_scripts, scripts_args):
  """
   Execute nse rules for host on ports.

   Parameters:
     nm (object): Nmap Portscanner object. Can execute nse scripts.
     ip (string): Ip of host
     values (dict): Related info to host
     scripts_names (list): List of scripts names to execute
     path_to_scripts (string): Path of nmap scripts folder
     scripts_args (string): Arguments used by scripts
  """

  # Get ports to attack
  ports = ','.join([str(p) for p in values['ports']])
 
  # Get scripts to execute
  # Path should be hidden better, or execute script installed in nerve!
  scripts_path = "" 
  for n in scripts_names:
    scripts_path += path_to_scripts + n + ','
  scripts_path = scripts_path[:-1] # do not use last ,
  scripts_syntax = "--script " + scripts_path # 
  
  # Start scan 
  nm.scan(ip, ports=ports, arguments='{} {}'.format(scripts_syntax, scripts_args)) 
  # logger.info('Scan command: ' + str(nm.command_line()))

  # Check if the host has not been  switched off in the middle of scan 
  test_scan_finished = nm.all_hosts()
  test_scan_finished_len = len(test_scan_finished)
  if test_scan_finished_len == 0:
    logger.info('Error during scan, host switched off')
  else:

    # Scan finished
    output_scan = nm._scan_result['scan'][ip]
    logger.info(output_scan)
    logger.info(output_scan.keys())
    logger.info('-----')
    
    #Check if NSE script was executed correctly
    for p in values['ports']:
      if 'script' in output_scan['tcp'][p]:

        # key is the script
        for key,result in output_scan['tcp'][p]['script'].items():
          logger.info('Sucessful scan')
          logger.info('Script {}, Output: {}'.format(key,result))
 
          # Obtain metadata of script from nse file
          nse_script = open(path_to_scripts + key + '.nse', 'r') 
          description = ''
          description_found = False
          description_done = False
          severity_level = 5 # PORQUE 5?
          severity_level_found = False
          confirm_description = ''
          confirm_found = False
          mitigation_description = ''
          mitigation_found = False

          #logger.info('Before traversing file')
          for line in nse_script:
            # All info has been found
            if description_done and severity_level_found and confirm_found and mitigation_found:
              break
            # Case when description is being read
            elif description_found and not description_done:
              if ']]' in line:
                description_done = True
              else:
                description += line
            # Info is missing and description is not being read
            else:             
              if 'description' == line[:11]:
                description_found = True
              if 'severity' == line[:8]: 
                line = line.replace(" ","")
                severity_level = int(line[-2])
                severity_level_found = True
              if 'confirm' == line[:7]: 
                 confirm_description = line.split('"')[1]
                 confirm_found = True
              if 'mitigation' == line[:10]:
                 mitigation_description = line.split('"')[1]
                 mitigation_found = True
      
          # Debug
          #logger.debug('Description: {}'.format(description))
          #logger.debug('Severity: {}'.format(severity_level))
          #logger.debug('Confirm: {}'.format(confirm_description))
          #logger.debug('Mitigation: {}'.format(mitigation_description))
          #logger.debug('--------')         
          #logger.debug('Description_found: {}'.format(description_found))
          #logger.debug('Description_done: {}'.format(description_done))
          #logger.debug('Severity_found: {}'.format(severity_level_found))
          #logger.debug('Confirm_found: {}'.format(confirm_found))
          #logger.debug('Mitigation_found: {}'.format(mitigation_found))
     
          # Obtain domain from parser
          parser = ScanParser(p, values)
          domain = parser.get_domain()
        
          # Save results on redis
          rds.store_vuln({
           'ip':ip,                                            # Check
           'port':p,                                           # Check
           'domain':domain,                                    # Check, es None en el caso que no halla
           'rule_id':key,                                      # A medias, Corresponde a un código de 8 caracteres. Sin embargo, creo que lo único que se hace con este es realizar un hash más adelante y no es relevante el largo. Por ahora para identificar cada script se usara el nombre. En el caso de múltipels scripts esto fallaría.
           'rule_sev':severity_level,                          # Check, usar campo 'severity' de scripts nse
           'rule_desc':description,                            # Check, Usar descripción del script de nmap
           'rule_confirm': confirm_description,                # Check, Descripción de algo, falta identificar de que, se puede dejar como string vacío supongo
           'rule_details': result,                             # Check, Resultados del script
           'rule_mitigation': mitigation_description           # Check, Descripción breve de como evitar el problema, permite string vacío creo
          })

      # Scripts were not executed correctly
      else:
        logger.debug('Error while executing scripts')
        logger.debug('Error for scripts {} on host {}, port {}'.format(scripts_names, ip, p))

  return

def attacker():
  """
   Daemon, launches scans.
  """

  count = 0
  logger.info('Attacker process started')
  
  while True:
    conf = rds.get_scan_config()
    
    if not conf:
      time.sleep(10)
      continue
    
    #run_python_rules(conf)
    run_NSE_rules()
    count += 1
      
    if count == conf['config']['scan_opts']['parallel_attack']:
      time.sleep(30)
      count = 0
    
      if threading.active_count() > 50:
        logger.debug('Sleeping for 30 seconds to control threads (Threads: {})'.format(threading.active_count()))  
        time.sleep(30)
    
