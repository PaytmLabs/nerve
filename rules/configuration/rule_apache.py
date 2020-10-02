from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_91Z0'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for Apache Web Server Misconfigurations'
    self.rule_confirm = 'Misconfigured Apache Server'
    self.rule_details = ''
    self.rule_mitigation = '''Apache Web Server is misconfigured and exposes one or more files \
related to configuration, statistics or example servlets.
Refer to an Apache Hardening Guideline for more information: https://geekflare.com/apache-web-server-hardening-security/'''
    self.rule_match_string = {
                              '/server-status':{
                                'app':'APACHE_SERVER_STATUS',
                                'match':['Total accesses', 'Parent Server Generation', 'Server uptime'],
                                'title':'Apache Server Status Page'
                              },
                              '/.htaccess':{
                                'app':'APACHE_HTACCESS_FILE',
                                'match':['RewriteEngine', 'IfModule'],
                                'title':'htaccess File'
                              },
                              '/server-info':{
                                'app':'APACHE_SERVER_INFO',
                                'match':['Apache Server Info', 'Request Hooks'],
                                'title':'Apache Server Info'
                              },
                              '/examples':{
                                'app':'APACHE_TOMCAT_EXAMPLES',
                                'match':['Serverlets examples', 'JSP Examples', 'WebSocket Examples'],
                                'title':'Apache Tomcat Examples'
                              },
                           }
    self.intensity = 1


  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module   = p.get_module()

    if 'http' not in module:
      return
    
    for uri, values in self.rule_match_string.items():
      app_title = values['title']
    
      resp = t.http_request(ip, port, uri=uri)
        
      if resp is not None:
        for match in values['match']:
          if match in resp.text:
            self.rule_details = 'Apache misconfiguration - {} at {}'.format(app_title, resp.url)
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
