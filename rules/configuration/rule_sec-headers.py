from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser
from core.logging import logger
class Rule:
  def __init__(self):
    self.rule = 'CFG_BS0F'
    self.rule_severity = 0
    self.rule_description = 'Checks if Security Headers exist'
    self.rule_confirm = 'Webserver is missing Security Headers'
    self.rule_details = ''
    self.rule_mitigation = '''Consider using security headers for your server. \
https://www.keycdn.com/blog/http-security-headers'''
    self.intensity = 1
    
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    module  = p.get_module()
    product  = p.get_product()
    
    if 'http' not in module:
      return
    
    resp = t.http_request(ip, port)
    
    if resp is None:
      return
    
    existing_headers = [k.lower() for k in resp.headers]
    security_headers = ['x-xss-protection', 'x-frame-options', 'x-content-type-options', 'strict-transport-security', 'content-security-policy', 'referrer-policy']
    
    for sh in security_headers:  
      if sh not in existing_headers:
        self.rule_details = 'Missing Security Header: ' + sh
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
