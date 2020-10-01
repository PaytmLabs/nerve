from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_FF00'
    self.rule_severity = 4
    self.rule_description = 'This rule checks for Open Wordpress Upload Directories'
    self.rule_confirm = 'Remote Wordpress has an Uploads Folder with Indexing Enabled'
    self.rule_details = ''
    self.rule_mitigation = '''Disable Directory Indexing on the Wordpress instance.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
   
    resp = t.http_request(ip, port, uri='/wp-content/uploads/')

    if resp and 'Index of /wp-content/uploads' in resp.text:
      self.rule_details = 'Found Uploads Directory at {}'.format(resp.url)
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
