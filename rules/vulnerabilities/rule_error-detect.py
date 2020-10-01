import random
import string

from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_AB1D'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for Information Revealing Errors'
    self.rule_confirm = 'Application is Leaking Information'
    self.rule_details = ''
    self.rule_mitigation = '''Server is configured with one or more frameworks which are incorrectly configured.
Disable any debug modes in the application and ensure proper error handling exists.
[!] {info} '''
    self.rule_match_string = {
                              self.generate_str():{
                                  'app':'DJANGO',
                                  'match':['Using the URLconf defined in', 
                                          'Django tried these URL patterns', 
                                          'You\'re seeing this error because you have <code>DEBUG'],
                                  'title':'Django Error'
                                },
                               self.generate_str():{
                                  'app':'MYSQL',
                                  'match':['MySQL Error', 'You have an error in your SQL syntax', 'mysql_fetch_array'],
                                  'title':'MySQL Error'
                                },
                               self.generate_str():{
                                  'app':'APACHE_TOMCAT',
                                  'match':['The full stack trace of the root cause is available', 'An exception occurred processing'],
                                  'title':'Apache Tomcat Error'
                                  },
                               self.generate_str():{
                                    'app':'APACHE_STRUTS',
                                    'match':['Struts has detected an unhandled exception', 'Stacktraces', 'struts.devMode=false'],
                                    'title':'Apache Struts Error'
                                  },
                                self.generate_str():{
                                    'app':'GENERIC',
                                    'match':['The debugger caught an exception'],
                                    'title':'Generic Error'
                                  },
                                '/public%c0':{
                                    'app':'OUCH_JS',
                                    'match':['copy exception into clipboard', 'Ouch container', 'Server/Request Data'],
                                    'title':'Ouch JS Error'
                                  },
                                '/public..':{
                                    'app':'OUCH_JS',
                                    'match':['copy exception into clipboard', 'Ouch container', 'Server/Request Data'],
                                    'title':'Ouch JS Error'
                                  },
                                '/php_errors.log':{
                                  'app':'PHP_ERROR_LOG',
                                  'match':['require_once', 'Fatal error', 'Stack trace'],
                                  'title':'PHP Error Log' 
                                }
                             }
    self.intensity = 2
    
  def generate_str(self):
    return '/' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
    
    if 'http' not in module:
      return
    
    resp = None

    for uri, values in self.rule_match_string.items():
      app_title = values['title']
      
      resp = t.http_request(ip, port, uri=uri)

      if resp is not None:
        for match in values['match']:
          if match in resp.text:
            self.rule_details = 'Information Leakage via {} at {}'.format(app_title, resp.url)   
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
