from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser
from db.db_ports import ldap_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_222E'
    self.rule_severity = 3
    self.rule_description = 'Checks for LDAP Ports'
    self.rule_confirm = 'Remote Server Exposes LDAP Port(s)'
    self.rule_details = ''
    self.rule_mitigation = '''Bind all possible network services to localhost, and allow those which require remote clients to connect.
[!] {info}'''
    self.intensity = 0
  
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)

    domain = p.get_domain()
    
    if port in ldap_ports:
    
      self.rule_details = 'Open Port: {} ({})'.format(port, ldap_ports[port])
      
      js_data = {
          'ip':ip,
          'port':port,
          'domain':domain,
          'rule_id':self.rule,
          'rule_sev':self.rule_severity,
          'rule_desc':self.rule_description,
          'rule_confirm':self.rule_confirm,
          'rule_details':self.rule_details,
          'rule_mitigation':self.rule_mitigation
        }
        
      rds.store_vuln(js_data)
      
    return
