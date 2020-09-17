from core.redis   import rds
from core.parser  import ScanParser, ConfParser
from core.triage  import Triage
from db.db_ports import vpn_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_ZII2'
    self.rule_severity = 2
    self.rule_description = 'Checks for VPN Ports'
    self.rule_confirm = 'Exposed VPN Port'
    self.rule_details = ''
    self.rule_mitigation = '''Bind all possible network services to localhost, and configure only those which require remote clients on an external interface.'''
    self.rule_match_port = vpn_ports
    self.intensity = 0
    
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    
    if port in vpn_ports:
      
      self.rule_details = 'Open Port: {} ({})'.format(port, self.rule_match_port[port])
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
