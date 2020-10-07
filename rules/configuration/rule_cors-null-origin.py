from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_32A0'
    self.rule_severity = 1
    self.rule_description = 'This rule checks if Cross Origin Resource Sharing policy trusts null origins'
    self.rule_confirm = 'CORS Policy Allows Null Origins'
    self.rule_details = ''
    self.rule_mitigation = '''Consider hardening your Cross Origin Resource Sharing Policy to define specific Origins \
https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'''
    self.intensity = 1
  
  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    module  = p.get_module()
    
    if 'http' not in module:
      return
    
    resp = None
    
    if domain:
      resp = t.http_request(domain, port, headers={'Origin':'null'})
    else:
      resp = t.http_request(ip, port, headers={'Origin':'null'})
    
    if resp is None:
      return
    
    if 'Access-Control-Allow-Origin' in resp.headers and resp.headers['Access-Control-Allow-Origin'] == 'null':
      self.rule_details = 'Remote Server accepted a NULL origin. Header used: "Origin: null"'
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