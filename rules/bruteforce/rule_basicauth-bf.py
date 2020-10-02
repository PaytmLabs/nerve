import requests

from core.redis    import rds
from core.triage   import Triage
from core.parser   import ScanParser, ConfParser
from db.db_paths   import COMMON_LOGIN_PATHS
from db.db_passwds import known_weak
from db.db_users   import known_users
from requests.auth import HTTPBasicAuth

class Rule:
  def __init__(self):
    self.rule = 'BRF_42FE'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if a Web Server is configured with Basic Authentication using weak credentials'
    self.rule_confirm = 'Basic Authentication with Weak Credentials'
    self.rule_details = ''
    self.rule_mitigation = '''Basic Authentication is configured on the remote server with weak credentials.
Change to a stronger password or alternatively use a Single Sign On solution.'''
    self.rule_doc_roots = COMMON_LOGIN_PATHS
    self.intensity = 3

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    c = ConfParser(conf)
    p = ScanParser(port, values)

    module = p.get_module()
    domain = p.get_domain()
    
    if not c.get_cfg_allow_bf():
      return
    
    if 'http' not in module:
      return
      
    usernames = c.get_cfg_usernames() + known_users
    passwords = c.get_cfg_passwords() + known_weak
    
    for uri in self.rule_doc_roots:  
      resp = t.http_request(ip, port, uri=uri)
    
      if resp is not None and resp.status_code == 401:
        if 'WWW-Authenticate' in resp.headers and resp.headers['WWW-Authenticate'].startswith('Basic'):  
          for username in usernames:
            for password in passwords:
              auth_attempt = requests.get(resp.url, auth = HTTPBasicAuth(username, password))
              if auth_attempt is not None and auth_attempt.status_code == 200:
                self.rule_details = 'Basic Authentication Credentials are set to {}:{} at {}'.format(username, password, uri)
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
