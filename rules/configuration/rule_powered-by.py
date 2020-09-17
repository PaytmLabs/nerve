from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_BZLS'
    self.rule_severity = 0
    self.rule_description = 'Checks if Banner Reveals Platform Version'
    self.rule_confirm = 'Identified Powered By Headers'
    self.rule_details = ''
    self.rule_mitigation = '''Disable Version Advertisement in the Web Server Configuration. \n
in IIS: https://stackoverflow.com/questions/3374831/in-iis-can-i-safely-remove-the-x-powered-by-asp-net-header \n
in ASP.NET: https://doc.sitecore.com/developers/90/platform-administration-and-architecture/en/remove-header-information-from-responses-sent-by-your-website.html 
'''
    self.intensity = 1
    
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    module  = p.get_module()
    product = p.get_product()
    
    if 'http' not in module:
      return
    
    resp = t.http_request(ip, port)
    
    if resp is None:
      return
    
    powered_by_headers = ['X-Powered-By', 'X-AspNet-Version']
    for poweredby_header in powered_by_headers:
      result = t.string_in_headers(resp, poweredby_header)
      if result:
        self.rule_details = '{}:{}'.format(poweredby_header, resp.headers.get(poweredby_header, None))
        js_data = {
                'ip':ip,
                'port':port,
                'domain':domain,
                'rule_id':self.rule,
                'rule_sev':self.rule_severity,
                'rule_desc':self.rule_description,
                'rule_confirm':self.rule_confirm,
                'rule_details':self.rule_details,
                'rule_mitigation':self.rule_mitigation
              }
        rds.store_vuln(js_data)
  
    return