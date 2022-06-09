import requests

from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser
from core.logging import logger


class Rule:
  def __init__(self):
    self.rule = 'MEDIUM CVEs'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for known Software Vulnerabilities'
    self.rule_confirm = 'Medium Vulnerabilities Found'
    self.rule_details = ''
    self.rule_mitigation = '''Server has 1 or more Medium (>= 4.0 and <= 6.9) CVEs associated with its version.
Update the software to the latest version'''
    self.intensity = 0

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    cpe = p.get_cpe()

    logger.info("[" + ip + ":" + str(port) + "] = domain: " + str(domain))
    logger.info("[" + ip + ":" + str(port) + "] = module: " + str(module))
    logger.info("[" + ip + ":" + str(port) + "] = values: " + str(values))
    logger.info("[" + ip + ":" + str(port) + "] = cpe: " + str(cpe))

    try:
      version_app = values['port_data'][port]['version']
    except:
      logger.error("[" + ip + ":" + str(port) + "] = something wrong in version reading, set to empty")
      version_app = ''
    
    if not cpe:
      logger.info("[" + ip + ":" + str(port) + "] = cpe empty, exited")
      return
    
    if not c.get_cfg_allow_inet():
      logger.info("[" + ip + ":" + str(port) + "] = inet not allowed, exited")
      return
   
    if version_app == '':
      logger.info("[" + ip + ":" + str(port) + "] = version_app empty, exited")
      return
 
    #if 'http' not in module:
    #  logger.info("[" + ip + ":" + str(port) + "] = http not in modules, exited")
    #  return 
    
    if t.has_cves(cpe, 4.0, 6.9):
      logger.info("[" + ip + ":" + str(port) + "] = Start checking CVEs related")
      self.rule_details = 'List of Vulnerabilities for this version: https://nvd.nist.gov/vuln/search/results?cpe_version={}'.format(cpe)  
      rds.store_vuln({
        'ip':ip,
        'port':port,
        'domain':domain,
        'rule_id':self.rule,
        'rule_sev':self.rule_severity,
        'rule_desc':self.rule_description,
        'rule_confirm':self.rule_confirm,
        'rule_details':self.rule_details,
        'rule_mitigation':self.rule_mitigation
      })
      
    return
