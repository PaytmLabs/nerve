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
          logger.debug('Script {}, Output: {}, Verify : {}'.format(key,result, vulnerable))
 
          if vulnerable == 'true': 
            # Save result in redis for further display
            save_result(key, result, metadata, ip, p, values, True)

          # Potential Threat, means tool does not support output result for script
          elif vulnerable == 'unknown':
            save_result(key, result, metadata, ip, p, values, False)
      
      # Script not executed correctly
      else:
        logger.debug('Error while executing script {} on host {} for port {}'.format(script, ip, p))
             

  return

def get_metadata(script, location):
  """
   Read through nse file to obtain corresponding metadata

   :param script str: Script name
   :param location str: Location where nse script resides, only supported values at the moment are "local" and "nmap" 
   :return result dict(str or int): Metadata values found

  """
  try:
    if location == 'local':
      script_path =  config.NSE_SCRIPTS_PATH + script + '.nse'
    elif location == 'nmap':
      script_path = config.NMAP_INSTALL_PATH + 'scripts/' + script + '.nse'
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
    severity_level = 5 # Undefined
    confirm_description = ''  
    mitigation_description = ''
    intensity = 3 # Default Highest possible, execute only on extremely aggressive

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
 
    # Check and format values values
    # Value must be between 0 - 6 
    if severity_level > 6 or severity_level < 0:
      severity_level = 5 # Undefined
    # Value must be between 0 - 3
    if intensity > 3 or intensity < 0:
      intensity = 3

    # Normalize values(confirm will be normalized down the line)
    description = re.sub(r"[^a-zA-Z0-9 ]", "", description)
    mitigation_description = re.sub(r"[^a-zA-Z0-9 ]", "", mitigation_description)

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
