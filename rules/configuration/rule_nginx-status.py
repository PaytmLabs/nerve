from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_ECC8'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for misconfigurations in Nginx'
    self.rule_details = ''
    self.rule_confirm = 'Nginx Server is misconfigured'
    self.rule_mitigation = '''Nginx is configured with default configurations, which exposes one or more status endpoints.
Nginx status may unintentionally reveal information which should not be remotely accessible.
The following article discusses the status module in-depth: http://nginx.org/en/docs/http/ngx_http_stub_status_module.html.'''
    self.rule_match_string = {
                              '/status':{
                                'app':'NGINX_STATUS',
                                'match':['Check upstream server', 'Nginx http upstream check status'],
                                'title':'Nginx connections page'
                              },   
                              '/nginx_status':{
                                'app':'NGINX_STATUS_PAGE',
                                'match':['server accepts handled requests', 'Active connections'],
                                'title':'Nginx Status Page',
                              },
                              '/static/resources/@':{
                                'app':'NGINX_INTERNAL_CONFIG',
                                'match':['access_log', 'error_log', 'proxy_pass', 'add_header'],
                                'title':'Nginx Internal Config',
                              },
                           }
    self.intensity = 1

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
            self.rule_details = 'Nginx Misconfiguration - {} at {}'.format(app_title, resp.url)
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