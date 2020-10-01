from ftplib import FTP

from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_ports import ftp_ports

class Rule:
  def __init__(self):
    self.rule = 'VLN_242C'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if FTP Server allows Anonymous Access'
    self.rule_details = ''
    self.rule_confirm = 'FTP Anonymous Access Allowed'
    self.rule_mitigation = '''FTP allows anonymous users access. Disable Anonymous FTP access if this is not a business requirement.'''
    self.rule_match_port = ftp_ports
    self.intensity = 0 

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    
    domain = p.get_domain()

    if port in self.rule_match_port:
      try:
        ftp = FTP(ip)
        res = ftp.login()
        if res:
          if '230' in res or 'user logged in' in res or 'successful' in res:
            self.rule_details = 'FTP with Anonymous Access Enabled'
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
      except:
        pass
    
    return
