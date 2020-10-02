from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_paths  import COMMON_WEB_PATHS
from core.logging import logger
class Rule:
  def __init__(self):
    self.rule = 'VLN_ZBKK'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for forgotten Intellij IDEA files'
    self.rule_confirm = 'Remote Server contains IDE related files'
    self.rule_details = ''
    self.rule_mitigation = '''Add the files to gitignore to prevent them from getting pushed.'''
    self.rule_match_string = ['ChangeListManager']
    self.uris = COMMON_WEB_PATHS
    self.intensity = 3

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
    
    resp = None

    for uri in self.uris:
      resp = t.http_request(ip, port, uri=uri+'/.idea/workspace.xml')
      if resp:
        for match in self.rule_match_string:
          if match in resp.text:
            self.rule_details = 'Found Intelli IDEA files at {}'.format(resp.url)
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
