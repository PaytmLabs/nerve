from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_ZEGE'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for accessible Open API (Swagger) Documentation'
    self.rule_confirm = 'Remote Server is exposing Swagger API'
    self.rule_details = ''
    self.rule_mitigation = '''Swagger API may have been incorrectly configured to allow access to untrusted clients. \
Check whether this can be restricted, as it may lead to attackers identifying your application endpoints.'''
    self.rule_match_string = {
                              '/v2/api-docs':{
                                'app':'SWAGGER',
                                'match':['"swagger":"2.0"'],
                                'title':'REST API Documentation'
                              }, 
                              '/help':{
                                'app':'ASPNET_WEBAPI_HELP',
                                'match':['ASP.NET Web API Help Page'],
                                'title':'ASP.NET API Docs'
                              },
                              '/api-docs':{
                                'app':'SWAGGER',
                                'match':['"swagger":"2.0"'],
                                'title':'REST API Documentation'
                              },
                               '/swagger/index.html':{
                                'app':'SWAGGER_ALT1',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
                              },
                               '/swagger-ui.html':{
                                'app':'SWAGGER_ALT2',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
                              },
                               '/api/swagger-ui.html':{
                                'app':'SWAGGER_ALT3',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
                              },
                               '/api-docs/swagger.json':{
                                'app':'SWAGGER_ALT4',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
                              },
                                '/swagger.json':{
                                'app':'SWAGGER_ALT5',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
                              },
                                '/swagger/v1/swagger.json':{
                                'app':'SWAGGER_ALT6',
                                'match':['Swagger UI', '"swagger"'],
                                'title':'REST API Documentation'
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
            self.rule_details = 'Identified an exposed {} at {}'.format(app_title, resp.url)
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
