import json

from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_ESTR'
    self.rule_severity = 4
    self.rule_description = 'Thisr ule checks for NodeJS Server.js file exposures'
    self.rule_confirm = 'Remote NodeJS Server is leaking server.js'
    self.rule_details = ''
    self.rule_mitigation = '''NodeJS has been configured to serve server.js which may allow attackers access to backend code.'''
    self.rule_match_string = [
      "require('http')",
      "module.exports",
      "server.listen",
      "http-proxy-middleware"
    ]
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
    
    if 'http' in module:
      resp = t.http_request(ip, port, uri='/server.js', follow_redirects=False)

      if resp is None:
        return
        
      for i in self.rule_match_string:
        if i in resp.text:
          self.rule_details = 'Identified a NodeJS Leakage at {} Indicator: {}'.format(resp.url, i)
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
