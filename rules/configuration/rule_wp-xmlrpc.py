from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_B3AB'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for XML-RPC Enabled interfaces in Wordpress'
    self.rule_confirm = 'Remote Server supports XML-RPC'
    self.rule_mitigation = '''Wordpress is configured with XML-RPC. XML-RPC can be used to cause Denial of Service and User Enumeration on a Wordpress server.
It is recommended to disable this interface if it is not utilized.
Refer to the following article for more information on XML RPC Attacks: https://kinsta.com/blog/xmlrpc-php/'''
    self.rule_details = ''
    self.intensity = 1
    

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if 'http' not in module:  
      return
    
    resp = t.http_request(ip, port, uri='/xmlrpc.php')
    if resp is not None and resp.status_code == 405:
      self.rule_details = 'Server responded to a GET request at /xmlrpc.php with status code: 405'
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