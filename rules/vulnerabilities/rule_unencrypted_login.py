from bs4 import BeautifulSoup
from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser
from db.db_ports import http_ports

class Rule:
  def __init__(self):
    self.rule = 'VLN_SKKF'
    self.rule_severity = 2
    self.rule_description = 'Checks for password forms in HTTP'
    self.rule_confirm = 'Unencrypted Login Form'
    self.rule_details = ''
    self.rule_mitigation = '''Website accepts credentials via HTML Forms, howeverm, it offers no encryptions and may allow attackers to intercept them.'''
    self.intensity = 1

  def contains_password_form(self, text):
    try:
      if text:
        soup = BeautifulSoup(text, 'html.parser')
        inputs = soup.findAll('input')
        if inputs:
          for i in inputs:
            if i.attrs.get('type') == 'password':
              return True
    except:
      pass
      
    return False

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    product  = p.get_product()

    
    if module == 'http' or port in http_ports:
      resp = t.http_request(ip, port, follow_redirects=False)
    
      if resp:
        form = self.contains_password_form(resp.text)
        if form:
          if not resp.url.startswith('https://'):
            self.rule_details = 'Login Page over HTTP'
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

