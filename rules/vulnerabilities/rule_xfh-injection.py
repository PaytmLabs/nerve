from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_ZD10'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for X-Forwarded-Host Injection'
    self.rule_confirm = 'Remote Server suffers from X-Forwarded-Host Injection'
    self.rule_details = ''
    self.rule_mitigation = '''Configure the server to not redirect based on arbitrary XFH headers provided by the user.
Refer to the following OWASP article for more information: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
    
    resp = t.http_request(ip, port, follow_redirects=False, headers={'X-Forwarded-Host':'www.nerve.local'})
    
    if resp is None:
      return
    
    if 'Location' in resp.headers and resp.headers['Location'] == 'www.nerve.local':
      self.rule_details = 'Server Redirected to an Arbitrary Location'
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
