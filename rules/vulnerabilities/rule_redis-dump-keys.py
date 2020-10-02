import socket

from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_ports  import database_ports

class Rule:
  def __init__(self):
    self.rule = 'VLN_E034'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for Open Redis Instances'
    self.rule_confirm = 'Remote Server Exposes Redis Keys'
    self.rule_details = ''
    self.rule_mitigation = '''Bind redis to the local network, and add authentication using --require-auth config parameter.'''
    self.intensity = 0

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if port != 6379 or module == 'redis':
      return
    
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    
      s.connect((ip, port))
      s.sendall(b'INFO\n')
      data = s.recv(1024)
      
      if data and 'redis_version' in str(data):
        self.rule_details = 'Redis is open and exposes the following: ..snip.. {} ..snip..'.format(str(data)[0:100])
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
    except:
      pass
  
    return


  