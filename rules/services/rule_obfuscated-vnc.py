from core.redis  import rds
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'SVC_0391'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for VNC services on obfuscated ports'
    self.rule_mitigation = '''VNC Running on non-standard ports is easy for attackers to find.
While it doesn't do harm changing the standard port from (default) 5900-5904, check whether VNC can be disabled, or allow acces only from trusted IP addresses.
'''
    self.rule_confirm = 'Remote Server Obfuscates VNC ports'
    self.rule_details = ''
    self.intensity = 0
    
  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
    
    if 'vnc' in module.lower() or 'X11' in module:
      if port not in (5800, 5801, 5802, 5803, 5804, 5900, 5901, 5902, 5903, 5904):
        self.rule_details = 'Server is hiding VNC behind remote port: {}'.format(port)
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
