from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_ZPZB'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for Carriage Return Line Feed Injections'
    self.rule_confirm = 'Remote Server suffers from CRLF Injection / HTTP Response Splitting'
    self.rule_details = ''
    self.rule_mitigation = '''Do not use CRLF characters in URL as HTTP stream
Refer to the OWASP CRLF Injection article for more information: https://owasp.org/www-community/vulnerabilities/CRLF_Injection#:~:text=The%20term%20CRLF%20refers%20to,in%20today's%20popular%20Operating%20Systems.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
    
    payload = '%0d%0aset-cookie:foo=inserted_by_nerve'
    resp = t.http_request(ip, port, follow_redirects=False, uri='/' + payload)
    
    if resp is None:
      return
    
    if 'set-cookie' in resp.headers and 'inserted_by_nerve' in resp.headers['set-cookie']: 
      self.rule_details = 'Identified CRLF Injection by inserting a Set-Cookie header'
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
