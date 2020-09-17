import psycopg2
from core.redis import rds
from core.triage import Triage
from core.parser import ScanParser, ConfParser
from db.db_passwds import known_weak
from db.db_users import known_users

class Rule:
  def __init__(self):
    self.rule = 'BRF_DC78'
    self.rule_severity = 4
    self.rule_description = 'Checks if PostgreSQL is configured with weak credentials'
    self.rule_confirm = 'Remote Server with weak PostgreSQL credentials'
    self.rule_details = ''
    self.rule_mitigation = '''PostgreSQL Allows connections with a weak password. 
PostgreSQL must not be listening on an external interface, and if required, it must allow only specific source IP addresses, in addition to a strong password authentication'''
    self.intensity = 3

  def psql_attack(self, ip, username, password):
    try:
      connection = psycopg2.connect(user=username, password=password, host=ip)
      if connection:
        connection.close()
        return True

    except Exception as e:
      return

    return False

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()

    if not c.get_cfg_allow_bf():
      return

    if port != 5432 or 'postgresql' not in module:
      return

    usernames = c.get_cfg_usernames() + known_users
    passwords = c.get_cfg_passwords() + known_weak

    for username in usernames:
      for password in passwords:
        if self.psql_attack(ip, username, password):
          self.rule_details = 'Credentials are set to {}:{}'.format(username, password)
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
