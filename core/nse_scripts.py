from core.parser import ScanParser
from core.logging import logger
from core.redis import rds

import sys
import os
import nmap
import config
import re

def verify_output(output, script):
  """
   Check if output corresponds to found vulnerability, only for supported scripts.

   :param output str: Scan result output.
   :param script str: Corresponding script name.
   :return vulnerability_found string: true,false,unknown value indicating if vulnerability was found during scan.
  """
  
  vulnerability_found = 'false'
  
  # Verification
  if script == 'ftp-steal':
    lines = output.split("\n")
    for line in lines:  
      if 'Lines containing keywords:' in line:
        vulnerability_found = 'true'

  elif script == 'ftp-brute':
    lines = output.split("\n")
    for line in lines:
      if 'Valid credentials' in line:
        vulnerability_found = 'true'

  elif script == 'sshv1':
    lines = output.split("\n")
    for line in lines:
      if 'true' in line:
        vulnerability_found = 'true'
  
  elif script == 'ssh-log4shell':
    lines = output.split("\n")
    for line in lines:
      if 'Password as payload succeeded. Weird' in line:
        vulnerability_found = 'true'

  else:
    vulnerability_found = 'unknown'

  return vulnerability_found

def get_args(script):
  """
   Get arguments of NSE script

   param script str: Name of nse script associated with args.
   return script_args str: NSE script args string in execution parameter format
  """
  script_args = '--script-args '

  if script == 'ftp-steal':
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

  elif script == 'ftp-brute':
    if hasattr(config, 'FTP_BRUTE_BRUTE_CREDFILE'):
      script_args += 'brute.credfile={},'.format(config.FTP_BRUTE_BRUTE_CREDFILE)
  
  # Get config arguments from script name 
  else:
    for name ,value in vars(config).items():
      name_match = script.replace("-","_").upper()
      if name.startswith(name_match):
         data = name.split(name_match + '_')
         arg_name = data[1].replace("_",".").lower()
         script_args += '{}={},'.format(arg_name, value)
    
  return script_args[:-1] 


def check_rule(script, metadata, ip, values, conf, location):
  """
   Launch attack to service

   :param script str: Script name or script path.
   :param metadata dict(str or int): Metadata of script
   :param ip str: Host ip
   :param values dict(str): Port scan info
   :param conf dict(str): Scan configuration info
   :param location str: Location where nse script resides, only supported values at the moment are "local" and "nmap" 
  """
  nm = nmap.PortScanner() 
  if location == 'local':
    script_syntax = '--script ' + config.NSE_SCRIPTS_PATH + script + '.nse'
  elif location == 'nmap':
    script_syntax = '--script ' + config.NMAP_INSTALL_PATH + 'scripts/' + script + '.nse'
  ports = ','.join([str(p) for p in values['ports']])

  # Start scan 
  script_args = get_args(script)
  if script_args == '--script-args':
    nm.scan(ip, ports=ports, arguments='{}'.format(script_syntax)) # Case when no arguments are given
  else:
    nm.scan(ip, ports=ports, arguments='{} {}'.format(script_syntax, get_args(script)))

  # Check if the host is switched off in the middle of scan 
  test_scan_finished = nm.all_hosts()
  test_scan_finished_len = len(test_scan_finished)
  if test_scan_finished_len == 0:
    logger.info('Error during scan, host switched off')
  else:
 
    # Scan finished
    output_scan = nm._scan_result['scan'][ip]
 
    #Check if NSE script was executed correctly
    for p in values['ports']:
      if 'script' in output_scan['tcp'][p]:
 
        # key = script
        for key,result in output_scan['tcp'][p]['script'].items():
          
          vulnerable = verify_output(result, key)
          result = {'description': description, 'severity_level': severity_level, 'confirm': confirm_description, 'mitigation': mitigation_description, 'intensity': intensity, 'categories': categories}
    return result
  
  # Error when reading file
  except IOError as e:
    return {'error': e}

# Return values that should be added to categories
# parse valores como '"a","b","c"'
# pero también funciona para partes con sintaxis de error como '"a""b""c"'. Esto no es legal en el lenguaje Lua pero igual se parsea acá. Creo que se caería el código, pero eso deja de ser mi problema xd. Creo que así debería funcionar.
# ACordarse de documentar esto.
def parse_categories(raw_data):
  """
   Auxiliary function to parse categories on nse scripts

   :param raw_data str: Raw line of data from nse script categories
   :return categories list(str): List of found categories in data line
  """
   categories = re.findall(r'\"(.*?)\"', raw_data)
   if categories:
     return categories
   categories_2 = re.findall(r"\'(.*?)\'", raw_data)
   if categories_2:
     return categories_2
   else:
     return []

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

  # If result is not confirmed mark as potencial vuln
  severity = metadata['severity_level']
  if not confirmed:
    severity = 6 # Potential
 
  # Save results on redis
  rds.store_vuln({
    'ip':ip,                                                 
    'port':port,                                             
    'domain':domain,                                         
    'rule_id':script,                                        # Script name as ID for now
    'rule_sev': severity,                                    
    'rule_desc': metadata['description'],                    
    'rule_confirm': re.sub(r"[^a-zA-Z0-9 ]", "", confirm),   # Falta verificar que pasa cuando es vacó
    'rule_details': result,                                 
    'rule_mitigation': metadata['mitigation']                
          })

  return
