from pymongo import MongoClient
from core.redis import rds
from core.parser import ScanParser, ConfParser
from db.db_passwds import known_weak
from db.db_users import known_users


class Rule:
  def __init__(self):
    self.rule = 'BRF_H7J5'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if MongoDB server is configured to accept remote connections using weak credentials'
    self.rule_confirm = 'Remote Server with weak MongoDB credentials'
    self.rule_details = ''
    self.rule_mitigation = '''MongoDB Server allows cremote onnections with a weak password. 
MongoDB must not be listening on an external interface, and if required, it must allow only specific source IP addresses, in addition to a strong password authentication.
Refer to the MongoDB hardening guide for more information: https://docs.mongodb.com/manual/administration/security-checklist/
'''
    self.intensity = 3

  def mongodb_attack(self, ip, port, username, password):

    if username == None and password == None:
      try:
        # Try MongoDB connection without authentication, using only IP/Port and no user/pass
        MongoClient(ip, port).list_database_names()
        return True

      except:
        return

    else:
      try:
        # Try MongoDB connection with authentication
        # Only admin DB is tested for brute forcing
        MongoClient('mongodb://{username}:{password}@{ip}/admin'.format(username=username, password=password, ip=ip))
        return True

      except:
        return

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()

    # When MongoDB authentication is enabled name=mongodb, when authentication is not enabled name=mongodb
    if port != 27017 or 'mongodb' not in module:
      return

    usernames = c.get_cfg_usernames() + known_users
    passwords = c.get_cfg_passwords() + known_weak

    # Check if MongoDB is configured with or without authentication
    if self.mongodb_attack(ip, port, None, None):
      rds.store_vuln({
        'ip': ip,
        'port': port,
        'domain': domain,
        'rule_id': self.rule,
        'rule_sev': self.rule_severity,
        'rule_desc': self.rule_description,
        'rule_confirm': 'Remote server with no authentication on MongoDB',
        'rule_details': 'MongoDB is configured with no authentication',
        'rule_mitigation': self.rule_mitigation
      })
      return

    if not c.get_cfg_allow_bf():
      return

    for username in usernames:
      for password in passwords:
        if self.mongodb_attack(ip, port, username, password):
          self.rule_details = 'MongoDB Credentials are set to: {}:{}'.format(username, password)
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

    return
