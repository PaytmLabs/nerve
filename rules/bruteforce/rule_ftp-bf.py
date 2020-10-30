import ftplib

from core.redis       import rds
from core.parser      import ScanParser, ConfParser
from db.db_passwds    import known_weak
from db.db_users      import known_users

class Rule:
  def __init__(self):
    self.rule = 'BRF_AZZ0'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if an FTP server is configured to accept remote connections using weak credentials'
    self.rule_confirm = 'Remote Server with weak FTP credentials'
    self.rule_details = ''
    self.rule_mitigation = '''FTP Server allows remote connections be accepted using a weak password. 
FTP should not be listening on an external interface. If required, it is recommended to allow only specific source IP addresses, in addition to a strong password authentication.'''
    self.intensity = 3

  def ftp_attack(self, ip, username, password):
    try:
      ftp = ftplib.FTP(ip, 
                       user=username, 
                       passwd=password, 
                       timeout=10)
  
      ftp.login()
      return True
    except:
      return False
    
    return False
      
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if not c.get_cfg_allow_bf():
      return
    
    if port != 21 or 'ftp' not in module:
      return
    
    usernames = c.get_cfg_usernames() + known_users
    passwords = c.get_cfg_passwords() + known_weak
    
    for username in usernames:
      for password in passwords:
        if self.ftp_attack(ip, username, password):
          self.rule_details = 'FTP Server Credentials are set to: {}:{}'.format(username, password)
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

