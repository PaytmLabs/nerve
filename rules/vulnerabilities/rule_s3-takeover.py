

from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_ZZ13'
    self.rule_severity = 3
    self.rule_description = 'Checks for Beanstalk Takeovers'
    self.rule_confirm = 'DNS Entry allows takeover of Beanstalk server'
    self.rule_details = ''
    self.rule_mitigation = '''Verify the DNS is in use, remove if unnecessary.\
Keeping a DNS record pointed at an S3 Bucket that does not exist, may lead to subdomain takeovers.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()

    if not domain:
      return
    
    resp = t.http_request(domain, port)
    
    if resp is None:
      return
    
    if resp.status_code == 404 and 'NoSuchBucket' in resp.text:
      self.rule_details = 'S3 Takeover at {}'.format(domain)
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
