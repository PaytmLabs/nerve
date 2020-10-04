import requests
import nmap
import config

from core.utils   import Utils
from core.triage  import Triage
from core.logging import logger
from db import db_ports

class Fingerprint():
  def __init__(self):
    self.t = Triage()

class Scanner():
  def __init__(self):
    self.nmap = nmap.PortScanner()
    self.nmap_args = {
      'unpriv_scan':'-sV -sT -n --max-retries 10 --host-timeout 60m',
      'priv_scan':'-sV -O -sT -n --max-retries 10 --host-timeout 60m'
    }
    self.utils = Utils()
    
  def scan(self, hosts, max_ports, custom_ports, interface=None):
    data = {}
    hosts = ' '.join(hosts.keys())
    extra_args = ''
    scan_cmdline = 'unpriv_scan'
    ports = ''
    
    if custom_ports:
      ports = '-p {}'.format(','.join([str(p) for p in set(custom_ports)]))
    
    elif max_ports:
      ports = '--top-ports {}'.format(max_ports)
    
    else:
      ports = '--top-ports 100'


    if interface:
      extra_args += '-e {}'.format(interface)
    
    if self.utils.is_user_root():
      scan_cmdline = 'priv_scan'
    
    result = {}
    
    try:
      result = self.nmap.scan(hosts, arguments='{} {} {}'.format(self.nmap_args[scan_cmdline], ports, extra_args))
    except nmap.nmap.PortScannerError as e:
      logger.error('Error with scan. {}'.format(e))
    
    if 'scan' in result:  
      for host, res in result['scan'].items():
        
        data[host] = {}
        data[host]['status'] = res['status']['state']
        data[host]['status_reason'] = res['status']['reason']
        data[host]['domain'] = None
        data[host]['os'] = None
        
        for i in res['hostnames']:
          if i['type'] == 'user':
            data[host]['domain'] = i['name']
            break
        
        if 'osmatch' in res and res['osmatch']:
          for match in res['osmatch']:
            if int(match['accuracy']) >= 90:
              data[host]['os'] = match['name']
              break
                 
        
        if 'tcp' in res:
          data[host]['port_data'] = {}
          data[host]['ports'] = set()
          
          for port, values in res['tcp'].items():
            if port and values['state'] == 'open':
              data[host]['ports'].add(port)    
              data[host]['port_data'][port] = {}
              data[host]['port_data'][port]['cpe'] = values['cpe']
              data[host]['port_data'][port]['module'] = values['name']
              data[host]['port_data'][port]['state']  = values['state']
              data[host]['port_data'][port]['version'] = values['version']
              data[host]['port_data'][port]['product'] = values['product']
    
    return data
