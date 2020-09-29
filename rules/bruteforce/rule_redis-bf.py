import socket

from core.redis    import rds
from core.triage   import Triage
from core.parser   import ScanParser, ConfParser
from db.db_passwds import known_weak
from core.logging import logger
class Rule:
  def __init__(self):
    self.rule = 'BRF_DD00'
    self.rule_severity = 4
    self.rule_description = 'Checks if Redis is configured with weak credentials'
    self.rule_confirm = 'Remote Server with weak Redis credentials'
    self.rule_details = ''
    self.rule_mitigation = '''Redis Server Allows connections with a weak password. 
Redis must not be listening on an external interface, and if required, it must allow only specific source IP addresses, in addition to a strong password authentication.'''
    self.intensity = 3

  def redis_attack(self, ip, port, password):
    try: 
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
      s.connect((ip, port))
      payload = 'AUTH {}\n'.format(password)
      s.sendall(payload.encode())
      data = s.recv(1024)
      logger.info(data)
      if 'OK' in data.decode('utf-8'):
        return True
    except Exception as e:
      logger.error(e)
      return False
    finally:
      s.close()
    return False
      
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if not c.get_cfg_allow_bf():
      return
    
    if port != 6379 or module != 'redis':  
      return
    
    passwords = c.get_cfg_passwords() + known_weak
    
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   
      s.connect((ip, port))
      s.sendall(b'INFO\n')
      data = s.recv(1024)
      if 'Authentication required' in data.decode('utf-8'):
        for password in passwords:  
          if self.redis_attack(ip, port, password):
            self.rule_details = 'Redis Credentials are set to: {}'.format(password)
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
    except:
      return
    
    return
        

