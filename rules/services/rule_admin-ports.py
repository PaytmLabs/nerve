from core.redis  import rds
from core.parser import ScanParser
from db.db_ports import admin_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_6509'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for open Remote Management Ports'
    self.rule_mitigation = '''Bind all possible services to localhost, and confirm only those which require remote clients are allowed remotely.'''
    self.rule_confirm = 'Remote Server Exposes Administration Port(s)'
    self.rule_details = ''
    self.intensity = 0
    
  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    
    if port in admin_ports:      
      self.rule_details = 'Server is listening on remote port: {} ({})'.format(port, admin_ports[port])
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
