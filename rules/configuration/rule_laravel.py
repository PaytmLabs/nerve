from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_823E'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for misconfigurations in Laravel'
    self.rule_confirm = 'Remote Server Misconfigured Laravel'
    self.rule_mitigation = '''Laravel has been misconfigured and may leak environment or log data. \
Use the Laravel Hardening Guidelines for reference: https://laravel.com/docs/7.x/configuration'''
    self.rule_details = ''
    self.rule_match_string = {
                              '/storage/logs/laravel.log':{
                                'app':'LARAVEL_FRAMEWORK_LOG',
                                'match':['Stack trace', 'Did you mean one of these?', 'ConsoleOutput'],
                                'title':'Laravel Framework Log'
                              },
                              '/.env':{
                                'app':'LARAVEL_FRAMEWORK_ENV',
                                'match':['MIX_PUSHER_APP_KEY', 'BROADCAST_DRIVER'],
                                'title':'Laravel Framework Env File'
                              },
                           }
    self.intensity = 1
    
    

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
    
    if 'http' not in module:
      return
    
    for uri, values in self.rule_match_string.items():
      app_title = values['title']
      
      resp = t.http_request(ip, port, uri=uri)
        
      if resp is not None:
        for match in values['match']:
          if match in resp.text:
            self.rule_details = 'Laravel Misconfiguration - {} at {}'.format(app_title, resp.url)
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