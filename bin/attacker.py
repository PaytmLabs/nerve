import time
import threading

from core.manager   import rule_manager
from core.parser    import ConfParser
from core.logging   import logger
from core.redis     import rds
from core.parser    import ScanParser

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

def run_NSE_rules():
  # Redis data
  data = rds.get_scan_data()
  #exclusions = rds.get_exclusions() # Not implemented for nmap yet
  nm = nmap.PortScanner()
  
  # Nmap args
  path_to_scripts = '/usr/share/nmap/scripts/'
  #name_of_scripts = ['ftp-anon.nse'] #['ftp-steal.nse'] ['ftp-brute'.nse']
  scripts_names = ['ftp-brute.nse','ftp-steal.nse']
  #scripts_args = "--script-args user=ftp_user,pass=ftp_user,dir=files"
  scripts_args = "--script-args brute.credfile=/home/ubuntu/Documents/creds.txt,user=ftp_user,pass=ftp_user,dir=files"
  #scripts_args = ""

  #logger.info('Scripts to be executed: {}'.format(scripts_path))
  #logger.info('Scripts args: {}'.format(scripts_args))

  # Nmap doesn't support multiple ports with different ports on one command.
  # Therefore multiple commands are ran in parallel for multiple hosts.
  # IPs and Ports
  for ip, values in data.items():
    #logger.info('Debug INFO:: Values: {}, ports: {}'.format(values, values['ports']))
    if 'ports' in values and len(values['ports']) > 0:  
      logger.info('Attacking Ports: {} of asset: {}'.format(values['ports'], ip))

      # Start new thread with NSE script
      thread = threading.Thread(target=NSE_rules, args=(nm, ip, values, scripts_names, path_to_scripts, scripts_args))
      thread.start()

def NSE_rules(nm, ip, values, scripts_names, path_to_scripts, scripts_args):
  # Get ports
  ports = ','.join([str(p) for p in values['ports']])
  
  # Get scripts to execute
  scripts_path = "" 
  for n in scripts_names:
    scripts_path += path_to_scripts + n + ','
  scripts_path = scripts_path[:-1] # Correct formatting
  scripts_syntax = "--script " + scripts_path # Por ahora se esta testeando solo 1 script con sus argumentos, a futuro verificar que esto funcione con multiples
  
  # Start scan 
  nm.scan(ip, ports=ports, arguments='{} {}'.format(scripts_syntax, scripts_args)) 
  logger.info(nm.command_line()) # Command ran

  # Check if the host has not been  switched off in the middle of scan  
  test_scan_finished = nm.all_hosts()
  test_scan_finished_len = len(test_scan_finished)
  if test_scan_finished_len == 0:
    logger.info('Error during scan, host switched off')
  else:
    output_scan = nm._scan_result['scan'][ip]
    logger.info(output_scan)
    logger.info(output_scan.keys())
    logger.info('-----')
    
    #Check if NSE script was executed correctly
    scan_results_test = "script"
    for p in values['ports']:
      if scan_results_test in output_scan['tcp'][p]:
        # Each key corresponds to scan results
        for key,result in output_scan['tcp'][p]['script'].items():
          logger.info('Sucessful scan')
          logger.info('Output {}: {}'.format(key,result))
 
          # Obtain metadata of script from nse file
          nse_script = open(path_to_scripts + key + '.nse', 'r') 
          description = ''
          description_found = False
          description_done = False
          severity_level = 5 # 
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
          #logger.info('Description: {}'.format(description))
          #logger.info('Severity: {}'.format(severity_level))
          #logger.info('Confirm: {}'.format(confirm_description))
          #logger.info('Mitigation: {}'.format(mitigation_description))
          #logger.info('--------')         
          #logger.info('Description_found: {}'.format(description_found))
          #logger.info('Description_done: {}'.format(description_done))
          #logger.info('Severity_found: {}'.format(severity_level_found))
          #logger.info('Confirm_found: {}'.format(confirm_found))
          #logger.info('Mitigation_found: {}'.format(mitigation_found))
     
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
      else:
        logger.info('Error while executing script')

  return

def attacker():
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
    
