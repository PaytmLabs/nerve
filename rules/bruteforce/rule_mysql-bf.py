import mysql.connector

from core.redis       import rds
from core.parser      import ScanParser, ConfParser
from db.db_passwds    import known_weak
from db.db_users      import known_users

class Rule:
  def __init__(self):
    self.rule = 'BRF_4F74'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if MySQL is configured to accept remote connections using weak credentials'
    self.rule_confirm = 'Remote Server with weak MySQL credentials'
    self.rule_details = ''
    self.rule_mitigation = '''MySQL Allows connections with a weak password. 
MySQL must not be listening on an external interface, and if required, it must allow only specific source IP addresses, in addition to a strong password authentication.
Refer to the MySQL Hardening Guideline for more information: https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html'''
    self.intensity = 3

  def mysql_attack(self, ip, username, password):
    try:
      conn = mysql.connector.connect(user=username, password=password, host=ip)
      if conn.is_connected():
        conn.close()
        return True
    except:
        pass
    
    return False
      
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()
    
    if not c.get_cfg_allow_bf():
      return
    
    if port != 3306 or 'mysql' not in module:
      return
    
    usernames = c.get_cfg_usernames() + known_users
    passwords = c.get_cfg_passwords() + known_weak
    
    for username in usernames:
      for password in passwords:
        if self.mysql_attack(ip, username, password):
          self.rule_details = 'MySQL Credentials are set to: {}:{}'.format(username, password)
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

