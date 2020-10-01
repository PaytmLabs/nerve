from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'VLN_EZSD'
    self.rule_severity = 4
    self.rule_description = 'This rule checks for exposed UNIX Filesystems'
    self.rule_confirm = 'UNIX File Disclosure'
    self.rule_details = ''
    self.rule_mitigation = '''Disable the ability to directly browse to file system paths'''
    self.rule_match_string = {
                              '/.ssh/authorized_keys':{
                                'app':'SSH_AUTH_KEYS',
                                'match':['ssh-rsa'],
                                'title':'SSH Authorized Keystore'
                                },
                             '/etc/hosts':{
                                'app':'LOCAL_HOSTS_FILE',
                                'match':['localhost is used to configure'],
                                'title':'Local Host Resolver'
                                },
                            '/etc/passwd':{
                                'app':'UNIX_PASSWD_FILE',
                                'match':['root:x:0:0'],
                                'title':'UNIX Local Users File'
                                },
                            '/etc/shadow':{
                                'app':'UNIX_SHADOW_FILE',
                                'match':['bin:x:', 'nobody:x:'],
                                'title':'UNIX Hashes File Leak'
                                },
                            '/.ssh/id_rsa':{
                                'app':'SSH_PRIVATE_KEY',
                                'match':['-----BEGIN RSA PRIVATE KEY-----'],
                                'title':'Private SSH Key Leak'
                                },
                            '/.ssh/id_rsa.pub':{
                                'app':'SSH_PUBLIC_KEY',
                                'match':['ssh-rsa'],
                                'title':'SSH Public Key'
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
   
    resp = None

    for uri, values in self.rule_match_string.items():
      app_title = values['title']
      
      resp = t.http_request(ip, port, uri=uri)
      
      if resp is not None:
        for match in values['match']:
          if match in resp.text:
            self.rule_details = 'UNIX File Disclosure - {} at {}'.format(app_title, resp.url)
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