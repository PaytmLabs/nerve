from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser


class Rule:
  def __init__(self):
    self.rule = 'VLN_4SD5'
    self.rule_severity = 2
    self.rule_description = 'Checks for Host Header Injections'
    self.rule_confirm = 'Identified Host Header Injection'
    self.rule_details = ''
    self.rule_mitigation = '''Redirect only to allowed hosts, otherwise ignore the Host Header.\
This may not indicate an immediate problem, but could potentially become an issue if any URLS are being constructed using the Host header.\
https://www.acunetix.com/blog/articles/automated-detection-of-host-header-attacks'''
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()

    if 'http' not in module:
      return

    resp = t.http_request(ip, port, follow_redirects=False,
                          headers={'X-Forwarded-Host':'112000as0az7s62s9d7.com',
                                   'Host': '112000as0az7s62s9d7.com'})

    if resp:
      if 'Location' in resp.headers and '112000as0az7s62s9d7.com' in resp.headers['Location']:
        self.rule_details = 'Host header injection'

        js_data = {
          'ip': ip,
          'port': port,
          'domain': domain,
          'rule_id': self.rule,
          'rule_sev': self.rule_severity,
          'rule_desc': self.rule_description,
          'rule_confirm': self.rule_confirm,
          'rule_details': self.rule_details,
          'rule_mitigation': self.rule_mitigation
        }

        rds.store_vuln(js_data)

    return
