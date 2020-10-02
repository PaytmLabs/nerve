from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_8BA9'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for misconfigurations in the blog platform Wordpress.'
    self.rule_confirm = 'Remote Server Wordpress is Misconfigured'
    self.rule_details = ''
    self.rule_mitigation = '''Wordpress may have been misconfigured and potentially leaks application data.
Remove any unnecessary files from the webserver which could potentially leak environment details of your Wordpress instance'''
    self.rule_match_string = {
                              '/wp-config.old':{
                                'app':'WORDPRESS',
                                'match':['wp-settings.php', 'DB_PASSWORD', 'MySQL settings'],
                                'title':'Wordpress Backup File'
                              },
                              '/wp-config.php':{
                                'app':'WORDPRESS',
                                'match':['wp-settings.php', 'DB_PASSWORD', 'MySQL settings'],
                                'title':'Wordpress Backup File'
                              },
                              '/wp-config.php.bak':{
                                'app':'WORDPRESS_PHP_BAK',
                                'match':['wp-settings.php', 'DB_PASSWORD', 'MySQL settings'],
                                'title':'Wordpress Backup File'
                              },
                              '/wp-config.php.old':{
                                'app':'WORDPRESS_PHP_OLD',
                                'match':['wp-settings.php', 'DB_PASSWORD', 'MySQL settings'],
                                'title':'Wordpress Backup File'
                              },
                              '/wp-config.php.save':{
                                'app':'WORDPRESS_SAVE',
                                'match':['wp-settings.php', 'DB_PASSWORD', 'MySQL settings'],
                                'title':'Wordpress Backup File'
                              },
                              '/wp-content/debug.log':{
                                'app':'WORDPRESS_DEBUG_LOG',
                                'match':['PHP Notice', 'Debugging_in_WordPress', 'PHP Warning', 'PHP Stack trace'],
                                'title':'Wordpress Debug Log'
                              },
                              '/wp-json/wp/v2/users':{
                                'app':'WORDPRESS_USERS',
                                'match':['"collection":[{"href":', '"_links":{"self":[{"href":""}]', 'avatar_urls', '"meta":[],'],
                                'title':'WordPress Username Disclosure'
                              },
                           }
    self.intensity = 2

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
            self.rule_details = 'Wordpress Misconfiguration - {} at {}'.format(app_title, resp.url)
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