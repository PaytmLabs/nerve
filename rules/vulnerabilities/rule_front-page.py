from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser


class Rule:
  def __init__(self):
    self.rule = 'VLN_65C8'
    self.rule_severity = 2
    self.rule_description = 'This rule checks for FrontPage configuration information disclosure'
    self.rule_confirm = 'FrontPage misconfiguration'
    self.rule_details = ''
    self.rule_mitigation = '''Ensure SharePoint is not anonymously accessible'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module:
      return

    resp = t.http_request(ip, port, uri='/_vti_inf.html')
    
    if not resp:
      return
    
    if 'Content-Length' in resp.headers and resp.headers['Content-Length'] == '247':
      self.rule_details = 'Exposed FrontPage at {}'.format(resp.url)
      rds.store_vuln({
        'ip': ip,
        'port': port,
        'domain': domain,
        'rule_id': self.rule,
        'rule_sev': self.rule_severity,
        'rule_desc': self.rule_description,
        'rule_confirm': self.rule_confirm,
        'rule_details': self.rule_details,
        'rule_mitigation': self.rule_mitigation
      })

    return
