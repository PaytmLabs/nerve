from core.redis   import rds
from core.parser  import ScanParser
from db.db_ports  import database_ports

class Rule:
  def __init__(self):
    self.rule = 'SVC_0C15'
    self.rule_severity = 3
    self.rule_description = 'This rule checks for open Database Ports'
    self.rule_confirm = 'Remote Server Exposes Database Port(s)'
    self.rule_details = ''
    self.rule_mitigation = '''Bind all possible database interfaces to localhost. 
If the database requires remote connections, allow only trusted source ip addresses.'''
    self.intensity = 0

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    
    for db_port, _ in database_ports.items():
      if port == db_port:
        self.rule_details = 'Server is listening on remote port: {} ({})'.format(port, database_ports[port])
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


  