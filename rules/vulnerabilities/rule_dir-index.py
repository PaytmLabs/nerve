from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_paths  import COMMON_WEB_PATHS

class Rule:
  def __init__(self):
    self.rule = 'VLN_Z013'
    self.rule_severity = 4
    self.rule_description = 'This rule checks for Open Directories via Directory Indexing'
    self.rule_confirm = 'Remote Server has Directory Indexing Enabled'
    self.rule_details = ''
    self.rule_mitigation = '''Disable Directory Indexing on the server. Directory Indexing can allow access to files on the server to untrusted sources.'''
    self.uris = COMMON_WEB_PATHS
    self.intensity = 3

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()

    if 'http' not in module: 
      return

    resp = None

    for uri in self.uris:
      resp = t.http_request(ip, port, uri=uri)
      if resp:
        for match in ('C=N;O=D', 'Index of /'):
          if match in resp.text:
            self.rule_details = 'Identified an Open Directory at {}'.format(resp.url)
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
            break
    
    return
