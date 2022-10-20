import sys
# Dotenv no quedo instalado en el path de las otras librerías, por lo que hay que añadir el path. En al instalación original no debería ocurrir este problema.
sys.path.append('/home/ubuntu/.local/lib/python3.6/site-packages')
from dotenv import load_dotenv

from core.parser import ScanParser
from core.logging import logger
from core.redis import rds


import os
import nmap

load_dotenv()

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
      if (not 'Lines containing keywords:' in line) and (not len(line.strip()) == 0):
        vulnerability_found = True

  elif script == 'ftp-brute':
    lines = output.split("\n")
    for line in lines:
      if 'Valid credentials' in line:
        vulnerability_found = True

  return vulnerability_found

def check_rule(script, script_args, metadata, ip, values, conf):
  """
   Launch attack to service

   :param script str: Script name
   :param scripts str: Scripts args [Actualmente se pueden ingresar args de otros scripts, lo que no tiene sentido]
   :param metadata dict(str or int): Metadata of script
   :param ip str: Host ip
   :param values dict(str): Port scan info
   :param conf dict(str): Scan configuration info 
  """
  nm = nmap.PortScanner() 

  script_syntax = '--script ' + os.environ['nmap_scripts_path'] + script + '.nse'
  script_args_syntax = '--script-args ' + script_args  
  ports = ','.join([str(p) for p in values['ports']])

  # Start scan
  nm.scan(ip, ports=ports, arguments='{} {}'.format(script_syntax, script_args_syntax))

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
          supported_scripts = ['ftp-steal', 'ftp-brute']
          if key in supported_scripts:
            vulnerable = verify_output(result, key)
            logger.debug('Verify output: {}, {}'.format(vulnerable, key))
 
            if vulnerable:
              # Save result in redis for further display
              save_result(key, result, metadata, ip, p, values)

          # ELSE POTENTIAL THREAT, RESULT OF OUTPUT PARSE NOT SUPPORTED BY TOOL ATM
      
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


def save_result(script, result, metadata, ip, port, values):
  """
   Save scan result in Redis.

   :param script str: Script name
   :param result str: Scan result
   :param metadata dict(str or int): Metadata of script
   :param ip str: Host ip
   :param port str: Host port
   :param values dict(str): Previous port scan info.
  """ 

  # Obtain domain from parser
  parser = ScanParser(port, values)
  domain = parser.get_domain()

  # In case no confirm description is given display scan details
  confirm = metadata['confirm']
  if confirm == '':
    confirm = result

  # Save results on redis
  rds.store_vuln({
    'ip':ip,                                                 # Check
    'port':port,                                             # Check
    'domain':domain,                                         # Check, es None en el caso que no halla
    'rule_id':script,                                        # A medias, Corresponde a un código de 8 caracteres. Sin embargo, creo que lo úni      co que se hace con este es realizar un hash más adelante y no es relevante el largo. Por ahora para identificar cada script se usara el nombre.       CREO QUE ESTO PUEDE FALLAR EN ALGUNOS CASOS.
    'rule_sev': metadata['severity_level'],                  # Check, usar campo 'severity' de scripts nse
    'rule_desc': metadata['description'],                    # Check, Usar descripción del script de nmap
    'rule_confirm': confirm,                     # Check, Descripción de algo, falta identificar de que, se puede dejar como strin      g vacío supongo
    'rule_details': result,                                  # Check, Resultados del script
    'rule_mitigation': metadata['mitigation']                # Check, Descripción breve de como evitar el problema, permite string vacío creo
          })

  return
