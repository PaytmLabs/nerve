import paramiko

from core.redis     import rds
from core.triage    import Triage
from core.parser    import ScanParser, ConfParser
from db.db_ports    import ssh_ports
from db.db_passwds  import known_weak
from db.db_users    import known_users
from core.utils     import Utils

class Rule:
  def __init__(self):
    self.rule = 'BRF_A953'
    self.rule_severity = 4
    self.rule_description = 'This rule checks if an SSH Server is configured to accept remote connections using weak credentials'
    self.rule_confirm = 'Remote server with weak credentials'
    self.rule_details = ''
    self.rule_mitigation = '''SSH Allows connections with a weak password. 
SSH must allow only trusted sources remote access, such as specific IP addresses, and use stronger authentication such as \
Public Key Authentication, in addition to a strong password authentication.
Refer to an OpenSSH Hardening Guidelines for more information: https://linux-audit.com/audit-and-harden-your-ssh-configuration/'''
    self.intensity = 3

  def ssh_attack(self, ip, port, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
      ssh.connect(ip, port=port, username=username, password=password, timeout=5)
      return True
    except paramiko.ssh_exception.NoValidConnectionsError:
      return False
    except paramiko.ssh_exception.AuthenticationException:
      pass
    except:
      pass
    finally:
      ssh.close()
    
    return False

  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)

    domain = p.get_domain()
    module = p.get_module()
    
    if not c.get_cfg_allow_bf():
      return
    
    if port in ssh_ports or 'ssh' in module:
      usernames = c.get_cfg_usernames() + known_users
      passwords = c.get_cfg_passwords() + known_weak
      
      output = t.run_cmd('ssh -o PreferredAuthentications=none -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o NoHostAuthenticationForLocalhost=yes user@"{}" -p "{}"'.format(ip, port))
      if output and 'password' in str(output): 
        for username in usernames:
          for password in passwords:
            if self.ssh_attack(ip, port, username, password):
              self.rule_details = 'SSH Server Credentials are set to {}:{}'.format(username, password)
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
