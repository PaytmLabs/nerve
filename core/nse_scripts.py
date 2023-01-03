from core.parser import ScanParser
from core.logging import logger
from core.redis import rds

import sys
import os
import nmap
import config

def verify_output(output, script):
  """
   Check if output corresponds to found vulnerability, only for supported scripts.

   :param output str: Scan result output
   :param script str: Corresponding script name
   :return vulnerability_found bool: Boolean indicating if vulnerability was found during scan.
   :return result_string str: If vulnerability was found returns parsed output if not empty string.
  """
  
  vulnerability_found = False
  
  # Verification
  if script == 'ftp-steal':
    lines = output.split("\n")
    for line in lines:  
      if 'Lines containing keywords:' in line:
        vulnerability_found = True

  elif script == 'ftp-brute':
    lines = output.split("\n")
    for line in lines:
      if 'Valid credentials' in line:
        vulnerability_found = True

  return vulnerability_found

def get_args():
  """
   Get arguments of NSE script

   return script_args str: NSE script args string in execution parameter format
  """
  script_args = '--script_args '
  if hasattr(config, 'FTP_STEAL_USER'):
    script_args += 'user={},'.format(config.FTP_STEAL_USER)
  else:
    script_args += 'user=root,'
  if hasattr(config, 'FTP_STEAL_PASS'):
    script_args += 'pass={},'.format(config.FTP_STEAL_PASS)
  else:
    script_args += 'pass=root,'
  if hasattr(config, 'FTP_STEAL_DIR'):
    script_args += 'dir={},'.format(config.FTP_STEAL_DIR)
  else:
    script_args += 'dir=.,'
  if hasattr(config, 'FTP_BRUTE_CREDFILE_PATH'):
    script_args += 'brute.credfile={},'.format(config.FTP_BRUTE_CREDFILE_PATH)
    
  return script_args[:-1] 


def check_rule(script, metadata, ip, values, conf):
  """
   Launch attack to service

   :param script str: Script name
   :param metadata dict(str or int): Metadata of script
   :param ip str: Host ip
   :param values dict(str): Port scan info
   :param conf dict(str): Scan configuration info 
  """
  nm = nmap.PortScanner() 
  
  script_syntax = '--script ' + config.NMAP_INSTALL_PATH + script + '.nse'
  ports = ','.join([str(p) for p in values['ports']])

  # Start scan 
  # Note: All scripts run with the same arguments
  nm.scan(ip, ports=ports, arguments='{} {}'.format(script_syntax, get_args()))

  # Check if the host is switched off in the middle of scan 
  test_scan_finished = nm.all_hosts()
  test_scan_finished_len = len(test_scan_finished)
  if test_scan_finished_len == 0:
    logger.info('Error during scan, host switched off')
  else:
 
    # Scan finished
    output_scan = nm._scan_result['scan'][ip]
    logger.debug('Raw Scan Output: ' + str(output_scan))
 
    #Check if NSE script was executed correctly
    for p in values['ports']:
      if 'script' in output_scan['tcp'][p]:
 
        # key = script
        for key,result in output_scan['tcp'][p]['script'].items():
          logger.info('Sucessful scan')
          logger.debug('Script {}, Output: {}'.format(key,result))
          
          # List of supported nse scripts by tool
          # Currently modified to test potential vulns
          supported_scripts = ['ftp-steal']
          if key in supported_scripts:
            vulnerable = verify_output(result, key)
            logger.debug('Verify output: {}, {}'.format(vulnerable, key))
 
            if vulnerable:
              # Save result in redis for further display
              save_result(key, result, metadata, ip, p, values, True)

          # Potential Threat, means tool does not support output result for script
          else:
            save_result(key, result, metadata, ip, p, values, False)
      
      # Script not executed correctly
      else:
        logger.debug('Error while executing scripts')
        logger.debug('Error for script {} on host {}, port {}'.format(script, ip, p))
             

  return

def get_metadata(script):
  """
   Read through nse file to obtain corresponding metadata

   :param scripts str: Script name
   :return result dict(str or int): Metadata values found

  """
  try:
    script_path = os.environ['nmap_scripts_path'] + script + '.nse'
    logger.debug('Script path: {}'.format(script_path))
    nse_script = open(script_path, 'r')

    # Delimeters
    description_found = False
    description_done = False
    severity_level_found = False
    confirm_found = False
    mitigation_found = False
    intensity_found = False

    # Info
    description = ''
    severity_level = 5 # 5 corresponds to undefined
    confirm_description = ''  
    mitigation_description = ''
    intensity = 0 # Lowest possible, always executes script

    # Traverse file
    for line in nse_script:
      # All info has been found
      if description_done and severity_level_found and confirm_found and mitigation_found and intensity_found:
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
        if 'intensity' == line[:9]:
          intensity = int(line[-2])
          intensity_found = True
  
    result = {'description': description, 'severity_level': severity_level, 'confirm': confirm_description, 'mitigation': mitigation_description, 'intensity': intensity}
    return result
  
  # Error when reading file
  except IOError as e:
    return {'error': e}


def save_result(script, result, metadata, ip, port, values, confirmed):
  """
   Save scan result in Redis.

   :param script str: Script name
   :param result str: Scan result
   :param metadata dict(str or int): Metadata of script
   :param ip str: Host ip
   :param port str: Host port
   :param values dict(str): Previous port scan info.
   :param confirmed bool: Boolean indicating if result is a confirmed vulnerability.
  """ 

  # Obtain domain from parser
  parser = ScanParser(port, values)
  domain = parser.get_domain()

  # In case no confirm description is given display scan details
  confirm = metadata['confirm']
  if confirm == '':
    confirm = result
  
  # If result if not confirmed mark as potential 
  severity = metadata['severity_level']
  if not confirmed:
    severity = 6 # Potential
 
  # Save results on redis
  rds.store_vuln({
    'ip':ip,                                                 # Check
    'port':port,                                             # Check
    'domain':domain,                                         # Check, es None en el caso que no halla
    'rule_id':script,                                        # A medias, Corresponde a un código de 8 caracteres. Sin embargo, creo que lo úni      co que se hace con este es realizar un hash más adelante y no es relevante el largo. Por ahora para identificar cada script se usara el nombre.       CREO QUE ESTO PUEDE FALLAR EN ALGUNOS CASOS.
    'rule_sev': severity,                                    # Check, usar campo 'severity' de scripts nse
    'rule_desc': metadata['description'],                    # Check, Usar descripción del script de nmap
    'rule_confirm': confirm,                     # Check, Descripción de algo, falta identificar de que, se puede dejar como strin      g vacío supongo
    'rule_details': result,                                  # Check, Resultados del script
    'rule_mitigation': metadata['mitigation']                # Check, Descripción breve de como evitar el problema, permite string vacío creo
          })

  return
