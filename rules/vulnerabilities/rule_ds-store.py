import string
import os
import struct
import random

from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser
from db.db_paths import COMMON_WEB_PATHS

class Rule:
  def __init__(self):
    self.rule = 'VLN_AS91'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for forgotten .DS_Store files'
    self.rule_confirm = '.DS_Store File Found'
    self.rule_details = ''
    self.rule_mitigation = '''A .DS_Store file is a special MacOSX file which reveals the files within the same folder where it lives. and may indicate what other files exists on the webserver.
This file occassionally get pushed by mistake due to not adding it to .gitignore.
Remove this file and add .DS_Store to .gitignore'''
    self.rule_match_string = '.DS_Store' 
    self.uris = COMMON_WEB_PATHS
    self.intensity = 2

  def is_file_ds_store(self, filename):  
    offset_position = 0 
    
    if len(filename) < offset_position + 2 * 4:
      return False

    if len(filename) < 36:
      return False
    
    value = filename[offset_position:offset_position + 2 * 4]

    magic1, magic2 = struct.unpack_from(">II", value)
    
    if not magic1 == 0x1 and not magic2 == 0x42756431:
      return False
      
    return True


  def generate_filename(self):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8))

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    module = p.get_module()
    domain = p.get_domain()
  
    if 'http' not in module:
      return

    for uri in self.uris:
      filename = self.generate_filename()
      resp = t.http_request(ip, port, uri=uri + '/.DS_Store')

      if resp:
        if os.path.exists(filename):
          os.remove(filename)
        
        with open(filename, "wb") as f:
          f.write(resp.content)
          f.close()

        with open(filename, 'rb') as f:
          if self.is_file_ds_store(f.read()):
            self.rule_details = 'Identified .DS_Store file at {}'.format(resp.url)
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
          
        os.remove(filename)
    return

        
