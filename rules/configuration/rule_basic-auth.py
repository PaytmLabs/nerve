from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_paths  import COMMON_LOGIN_PATHS

class Rule:
  def __init__(self):
    self.rule = 'CFG_D2A9'
    self.rule_severity = 2
    self.rule_description = 'This rule checks if a Web Server has Basic Authentication enabled'
    self.rule_confirm = 'Basic Authentication is Configured'
    self.rule_details = ''
    self.rule_mitigation = '''Basic authentication is a simple authentication scheme built into the HTTP protocol.
The client sends HTTP requests with the Authorization header that contains the word Basic word followed by a \
space and a base64-encoded string username:password
Basic Authentication does not have brute force protection mechanisms, and may potentially be a target for attackers'''
    self.rule_doc_roots = COMMON_LOGIN_PATHS
    self.intensity = 2

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
            
    if 'http' not in module:
      return
    
    for uri in self.rule_doc_roots:
      
      resp = t.http_request(ip, port, uri=uri)
      
      if resp is not None and resp.status_code == 401:
        if 'WWW-Authenticate' in resp.headers:
          header = resp.headers['WWW-Authenticate']
          if header.startswith('Basic'):
            self.rule_details = '{} at {}'.format(self.rule_confirm, resp.url)
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
