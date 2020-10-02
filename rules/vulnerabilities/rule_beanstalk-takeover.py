import dns.resolver

from core.redis   import rds
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_ZZ13'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for Beanstalk DNS Takeovers'
    self.rule_confirm = 'DNS Entry allows takeover of Beanstalk server'
    self.rule_details = ''
    self.rule_mitigation = '''Verify the DNS is in use, remove the record if unnecessary.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
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
            self.rule_details = 'Beanstalk DNS Takeover at {} ({})'.format(domain, resolved)
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
          except:
            continue
    except:
      return
          
    return
