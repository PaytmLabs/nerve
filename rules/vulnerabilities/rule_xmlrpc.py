from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_FAZZ'
    self.rule_severity = 2
    self.rule_description = 'Checks for XMLRPC Interfaces'
    self.rule_confirm = 'Remote Server has XMLRPC Interface enabled'
    self.rule_details = ''
    self.rule_mitigation = '''Restrict access to the XMLRPC Interface \
or disabled it completely if not in use.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
    
    resp = t.http_request(ip, port, uri='/xmlrpc.php')
    
    if resp is None:
      return
    
    if resp.status_code == 405:
      self.rule_details = 'Server Allows XMLRPC Connections'
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
