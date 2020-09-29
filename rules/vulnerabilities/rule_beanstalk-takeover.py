import dns.resolver

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
    self.rule_mitigation = '''Verify the DNS is in use, remove the record if unnecessary.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()

    if not domain:
      return
  
    try:
      for resolved in dns.resolver.query(domain, 'CNAME'):
        resolved = str(resolved)
        if 'elasticbeanstalk.com' in resolved:
          try:
            dns.resolver.query(resolved)
          except dns.resolver.NXDOMAIN:
            info = 'Beanstalk Takeover'
            self.rule_details = 'Beanstalk Takeover at {} ({})'.format(domain, resolved)
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
          except:
            continue
    except:
      return
          
    return
