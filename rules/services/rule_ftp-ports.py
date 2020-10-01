from core.redis   import rds
from core.parser  import ScanParser
from db.db_ports  import ftp_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_C74A'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for open FTP Ports'
    self.rule_confirm = 'Remote Server Exposes FTP Port(s)'
    self.rule_details = ''
    self.rule_mitigation = '''Ensure at the bare minimum FTP is over SSL, and only allow trusted clients to connect to it over the network.'''
    self.rule_match_string = ftp_ports
    self.intensity = 0

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)

    domain = p.get_domain()
    
    if port in ftp_ports:
      self.rule_details = 'Server is listening on remote port:{} ({})'.format(port, ftp_ports[port])
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
  