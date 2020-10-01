from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser

class Rule:
  def __init__(self):
    self.rule = 'DSC_FB18'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for the exposure of Known Platform based on response header signatures'
    self.rule_confirm = 'Identified a Known Platform via its Headers'
    self.rule_details = ''
    self.rule_mitigation = '''Identify whether the application in question is supposed to be exposed to the network.'''
    self.rule_match_string = {
                            'Jenkins':{
                              'app':'JENKINS',
                              'match':['X-Jenkins', 'X-Hudson'],
                              'title':'Build Server'
                            },
                            'Artifactory':{
                              'app':'ARTIFACTORY',
                              'match':['X-Artifactory-Id', '/artifactory/webapp/'],
                              'title':'Software Artifacts server'
                            },
                            'Kubernetes':{
                              'app':'KUBERNETES',
                              'match':['kubernetes-master'],
                              'title':'Container Orchestration'
                            },
                            'Docker':{
                              'app':'DOCKER',
                              'match':['Server: Docker', 'Docker'],
                              'title':'Containers'
                            },
                            'etcd':{
                              'app':'ETCD',
                              'match':['etcd'],
                              'title':'K/V Storage'
                            },
                            'Grafana':{
                              'app':'GRAFANA',
                              'match':['grafana'],
                              'title':'Graph Platform'
                            },
                            'Prometheus':{
                              'app':'PROMETHEUS',
                              'match':['Prometheus'],
                              'title':'Monitoring System'
                            },
                            'Kibana':{
                              'app':'KIBANA',
                              'match':['kibana','kbn-name'],
                              'title':'Analytics'
                            },
                            'phpMyAdmin':{
                              'app':'PHPMYADMIN',
                              'match':['phpMyAdmin'],
                              'title':'MySQL Admin Panel'
                            },
                            'OpenNMS':{
                              'app':'OPENNMS',
                              'match':['opennms'],
                              'title':'Monitoring System'
                            },
                            'Observium':{
                              'app':'OBSERVIUM',
                              'match':['observium'],
                              'title':'Monitoring System'
                            },
                            'MongoDB':{
                              'app':'MONGODB',
                              'match':['MongoDB'],
                              'title':'Database'
                            },
                            'Zabbix':{
                              'app':'ZABBIX',
                              'match':['zabbix'],
                              'title':'Monitoring System'
                            },
                            'Weblogic':{
                              'app':'WEBLOGIC',
                              'match':['10.3.6.0.0', '12.1.3.0.0', '12.2.1.1.0', '12.2.1.2.0'],
                              'title':'Weblogic' 
                            },
                            'Webmin':{
                              'app':'WEBMIN',
                              'match':['MiniServ'],
                              'title':'Webmin' 
                            },
                            'Graylog':{
                              'app':'GRAYLOG',
                              'match':['X-Graylog-Node-ID'],
                              'title':'Graylog'
                            },
                            'SpringEureka':{
                              'app':'SPRING_EUREKA',
                              'match':['Instances currently registered with Eureka'],
                              'title':'Monitoring System'
                            },
                            'Pi-Hole':{
                              'app':'PIHOLE',
                              'match':['X-Pi-hole'],
                              'title':'Pi-Hole DNS'
                            },
                            'Docker Registry':{
                              'app':'DOCKER_REGISTRY',
                              'match':['Docker-Distribution-Api-Version', 'registry/2.0'],
                              'title':'Docker Registry'
                            },
                            'Symfony':{
                              'app':'SYMFONY',
                              'match':['X-Debug-Token-Link'],
                              'title':'Symfony Debug'
                            },
                            'MongoExpress':{
                              'app':'MONGO_EXPRESS',
                              'match':['Set-Cookie: mongo-express='],
                              'title':'Mongo Express'
                            },
                            'OpenVAS':{
                            'app':'OPENVAS',
                            'match':['Greenbone Security Manager'],
                            'title':'OpenVAS Panel'
                            },
                            'Adminer':{
                              'app':'ADMINER',
                              'match':['adminer.org'],
                              'title':'Adminer PHP'
                            }
                      }
    self.intensity = 1

  def check_rule(self, ip, port, values, conf):
    p = ScanParser(port, values)
    t = Triage()
    
    domain = p.get_domain()
    module = p.get_module()
    
    if 'http' not in module:
      return
   
    resp = t.http_request(ip, port)
    
    for _, val in self.rule_match_string.items():
      app_title = val['title']
            
      for match in val['match']:  
        if resp and t.string_in_headers(resp, match):
          self.rule_details = 'Exposed {} at {}'.format(app_title, resp.url)
          rds.store_vuln({
            'ip':ip,
            'port':port,
            'domain':domain,
            'rule_id':self.rule,
            'rule_sev':self.rule_severity,
            'rule_desc':self.rule_description,
            'rule_details':self.rule_details,
            'rule_mitigation':self.rule_mitigation
          })
          break
    return 

  
