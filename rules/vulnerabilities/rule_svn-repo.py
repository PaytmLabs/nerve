from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser
from core.utils  import Utils

class Rule:
  def __init__(self):
    self.rule = 'VLN_BLKK'
    self.rule_severity = 4
    self.rule_description = 'This rule checks for open SVN Repositories'
    self.rule_confirm = 'SVN Repository Found'
    self.rule_details = ''
    self.rule_mitigation = '''Block remote access to the Subversion repository.'''
    self.intensity = 0
                                    
  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if 'http' not in module:
      return
    
    resp = t.http_request(ip, port, uri='/.svn/text-base')

    if resp and 'Index of /' in resp.text:
      self.rule_details = 'SVN Repository exposed at {}'.format(resp.url)
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

