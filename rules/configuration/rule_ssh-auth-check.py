from core.redis      import rds
from core.triage     import Triage
from core.parser     import ScanParser, ConfParser
from db.db_ports     import ssh_ports

class Rule:
  def __init__(self):
    self.rule = 'CFG_FOQW'
    self.rule_severity = 3
    self.rule_description = 'Checks if SSH password authentication is supported'
    self.rule_confirm = 'Remote Server Supports SSH Passwords'
    self.rule_details = ''
    self.rule_mitigation = '''SSH Allows Password authentication, this is considered bad security practice. 
SSH Key based authentication should be enabled on the server, and passwords should be disabled.'''
    self.intensity = 0
    
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    
    if port in ssh_ports and t.is_ssh(ip, port):
      output = t.run_cmd('ssh -o PreferredAuthentications=none -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o NoHostAuthenticationForLocalhost=yes user@"{}" -p "{}"'.format(ip, port))
      if output and 'password' in str(output): 
        self.rule_details = p.get_product()
        
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
