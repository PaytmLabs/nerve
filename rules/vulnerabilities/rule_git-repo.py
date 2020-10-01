from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_paths  import COMMON_WEB_PATHS
from core.logging import logger

class Rule:
  def __init__(self):
    self.rule = 'VLN_92F9'
    self.rule_severity = 4
    self.rule_description = 'This rule checks for open Git Repositories'
    self.rule_confirm = 'Remote Server Exposes Git Repository'
    self.rule_details = ''
    self.rule_mitigation = '''Git repository was found to be accessible. \
Configure the server in a way that makes git repository unreachable to untrusted clients'''
    self.intensity = 3
    self.uris = COMMON_WEB_PATHS
  
  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if 'http' not in module:
      return
    
    resp = None
    
    for uri in self.uris: 
      resp = t.http_request(ip, port, uri=uri + '/.git/HEAD')

      if resp and resp.text.startswith('ref:'):        
        self.rule_details = 'Identified a git repository at {}'.format(resp.url)
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
