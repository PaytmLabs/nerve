from core.redis   import rds
from core.parser  import ScanParser
from db.db_ports import smb_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_Z115'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for open SMB Ports'
    self.rule_confirm = 'Remote Server Exposes SMB Port(s)'
    self.rule_details = ''
    self.rule_mitigation = '''Bind all possible network services to localhost, and configure only those which require remote clients on an external interface.'''
    self.intensity = 0

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    
    if port in smb_ports:        
      self.rule_details = 'Server is listening on remote port: {} ({})'.format(port, smb_ports[port])
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
