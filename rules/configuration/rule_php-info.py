from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_BS3R'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for misconfigurations in PHP'
    self.rule_confirm = 'PHP Information Leakage'
    self.rule_details = ''
    self.rule_mitigation = '''The Remote Server's PHP is leaking out environment information, which may under \
certain situations reveal sensitive data such as environment variables, modules installed, etc.
Disable PHP info by either adding
`disable_functions = phpinfo`
in php.ini file 
OR
`php_value disable_functions phpinfo`
in .htaccess file.
'''
    self.rule_match_string = {
                              '/phpinfo.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/php/info.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/info.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/php.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/infophp.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/php_info.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/test.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/phpversion.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                              '/pinfo.php':{
                                'app':'PHP_INFO',
                                'match':['PHP License'],
                                'title':'Default PHP environment page'
                              },
                           }
    self.intensity = 3
    

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module:
      return
      
    for uri, values in self.rule_match_string.items():
      app_title = values['title']
      
      resp = t.http_request(ip, port, uri=uri)
        
      if resp is not None:
        for match in values['match']:
          if match in resp.text:
            self.rule_details = 'PHP Misconfiguration - {} at {}'.format(app_title, resp.url)
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