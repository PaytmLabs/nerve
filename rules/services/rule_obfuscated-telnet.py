from core.redis  import rds
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'SVC_2993'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for Telnet services on obfuscated ports'
    self.rule_mitigation = '''Telnet Running on non-standard ports is easy for attackers to find.
While it doesn't do harm changing the standard port from (default) 23, check whether Telnet can be disabled, or allow acces only from trusted IP addresses.
'''
    self.rule_confirm = 'Remote Server Obfuscates Telnet ports'
    self.rule_details = ''
    self.intensity = 0
    
  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
    
    if 'telnet' in module or 'telnetd' in module:
      if port != 23:
        self.rule_details = 'Server is hiding Telnet behind remote port: {}'.format(port)
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
