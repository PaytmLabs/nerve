from core.redis  import rds
from core.triage import Triage
from core.parser import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'CFG_E9AF'
    self.rule_severity = 0
    self.rule_description = 'This rule checks if a Default Page is Served by a Web Server'
    self.rule_confirm = 'Unmaintained Webserver'
    self.rule_details = ''
    self.rule_mitigation = '''Server is configured with the default web server page. 
This may indicate a forgotten/unmaintained server, and may not necessarily pose a security concern.'''
    self.rule_match_string  = {
                    'Apache':{
                      'app':'APACHE',
                      'match':['Are you the administrator?'],
                      'title':'Apache Default Page'
                    },
                    'Apache2':{
                      'app':'APACHE2',
                      'match':['Apache 2 Test Page', 'It works!'],
                      'title':'Apache2 Default Page'
                    },
                    'Apache2 Debian':{
                      'app':'APACHE2_DEBIAN',
                      'match':['Apache2 Debian Default Page'],
                      'title':'Apache2 Debian Default Page'
                    },
                    'Apache2 Ubuntu':{
                      'app':'APACHE2_UBUNTU',
                      'match':['Apache2 Ubuntu Default Page'],
                      'title':'Apache2 Ubuntu Default Page'
                    },
                    'Nginx':{
                      'app':'NGINX',
                      'match':['Welcome to nginx!'],
                      'title':'Nginx Default Page'
                    },
                    'NodeJS Express':{
                      'app':'NODEJS_EXPRESS',
                      'match':['Welcome to Express'],
                      'title':'NodeJS Express Default Page'
                    },
                    'Lighttpd':{
                      'app':'LIGHTTPD',
                      'match':['Lighttpd server package', 'lighty-enable-mod'],
                      'title':'Lighttpd Default Page'
                    },
                    'IIS7':{
                      'app':'MS_IIS',
                      'match':['img src="welcome.png" alt="IIS7"', 'img src="iisstart.png" alt="IIS"'],
                      'title':'MS IIS Default Page'
                    },
                    'Django':{
                      'app':'DJANGO',
                      'match':['The install worked successfully!'],
                      'title':'Django Default Page'
                    },
                    'ASP.NET':{
                      'app':'ASPNET',
                      'match':['ASP.NET is a free web framework'],
                      'title':'ASP.NET Default Page'
                    },
                    'LightSpeed':{
                      'app':'LIGHTSPEED',
                      'match':['installed the OpenLiteSpeed Web Server!'],
                      'title':'LightSpeed Default Page'
                    },
                    'Fedora':{
                      'app':'FEDORA',
                      'match':['Fedora Test Page'],
                      'title':'Fedora Default Page'
                    },
                    'RHEL':{
                      'app':'RHEL',
                      'match':['Red Hat Enterprise Linux Test Page'],
                      'title':'Red Hat Default Page'
                    },
                    'OpenResty':{
                      'app':'OPENRESTY',
                      'match':['flying OpenResty'],
                      'title':'OpenResty Default Page'
                    }
                  }
    self.intensity = 1
    
  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module   = p.get_module()
    
    if 'http' not in module:
      return
    
    resp = t.http_request(ip, port, uri='/')
    
    if resp is None:
      return
    
    for app, val in self.rule_match_string.items():
      app_title = val['title']
      
      for match in val['match']:
        if match in resp.text:
          self.rule_details = 'Identified a default page: {} Indicator: "{}" ({})'.format(resp.url, match, app_title)
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
