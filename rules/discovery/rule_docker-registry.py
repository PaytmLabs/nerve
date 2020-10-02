from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'DSC_55A9'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for the exposure of Docker Registry Endpoints'
    self.rule_confirm = 'Identified a Docker Registry Endpoint'
    self.rule_details = ''
    self.rule_mitigation = '''Identify whether the application in question is supposed to be exposed to the network.'''
    self.rule_match_string = {    
    '/v2/_catalog':{
      'app':'DOCKER_REGISTRY_LIST',
      'match':['"repositories":'],
      'title':'Docker Registry List'
      },
    }
    self.intensity = 1
    
  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    module  = p.get_module()
    
    if 'http' in module:
      for uri, values in self.rule_match_string.items():
        app_title = values['title']
  
        resp = t.http_request(ip, port, uri=uri)

        if resp is not None:
          for match in values['match']:
            if match in resp.text:
              self.rule_details = 'Exposed {} at {}'.format(app_title, resp.url)
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
