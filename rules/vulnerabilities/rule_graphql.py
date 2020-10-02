from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_FBQP'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for open GraphQL Interfaces'
    self.rule_confirm = 'Exposed GraphQL Interface'
    self.rule_details = ''
    self.rule_mitigation = '''Restrict access to the GraphQL Interface to trusted sources \
or disabled it completely if not in use.'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module: 
      return
    
    graphql_uris = ['/graphql', '/graphiql'] 
    resp = None
    
    for uri in graphql_uris:
      resp = t.http_request(ip, port, uri=uri)

      if resp is None:
        return
      
      if resp.status_code == 400 and 'GET query missing.' in resp.text:
        self.rule_details = 'GraphQL Enabled on the Server at {}'.format(resp.url)
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
      
    return
