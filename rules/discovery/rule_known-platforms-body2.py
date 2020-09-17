from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser, ConfParser

class Rule:
  def __init__(self):
    self.rule = 'DSC_38A9'
    self.rule_severity = 1
    self.rule_description = 'Checks for Known Panels'
    self.rule_confirm = 'Identified a Known Web Panel'
    self.rule_details = ''
    self.rule_mitigation = '''Identify whether the application in question is supposed to be exposed to the local network.'''
    self.rule_match_string = {
                              '/phpmyadmin/index.php':{
                                'app':'PHP_MYADMIN',
                                'match':['Welcome to phpMyAdmin', 'phpmyadmin.css', 'Server Choice', 'phpMyAdmin is more friendly with'],
                                'title':'Administration of MySQL'
                                },
                               '/pma/index.php':{
                                'app':'PHP_MYADMIN',
                                'match':['Welcome to phpMyAdmin', 'phpmyadmin.css', 'Server Choice', 'phpMyAdmin is more friendly with'],
                                'title':'Administration of MySQL'
                                },
                              '/phpmoadmin':{
                                'app':'PHP_MOADMIN',
                                'match':['mongo_rows'],
                                'title':'Administration of MongoDB'
                                },
                              '/moadmin':{
                                'app':'PHP_MOADMIN',
                                'match':['mongo_rows'],
                                'title':'Administration of MongoDB'
                                },
                              '/admin':{
                                'app':'FLYWAY',
                                'match':['configprops', 'auditevents'],
                                'title':'Flyway'
                              },
                              '/zabbix/index.php':{
                                'app':'ZABBIX',
                                'match':['Zabbix SIA'],
                                'title':'Zabbix Server'
                              },
                              '/jenkins':{
                                'app':'JENKINS',
                                'match':['Dashboard [Jenkins]', 'Deployables [Jenkins]', '/jenkins/static/'],
                                'title':'Jenkins'
                              },
                              '/grid/console':{
                                'app':'SELENIUM_GRID',
                                'match':['DefaultRemoteProxy', 'hubConfig', 'grid/register', 'DefaultGridRegistry'],
                                'title':'Selenium Grid'
                              },        
                              '/elmah.axd':{
                                'app':'ELMAH',
                                'match':['Powered by ELMAH', 'Error Log or'],
                                'title':'Elmah'
                              },
                              '/solr':{
                                'app':'APACHE_SOLR',
                                'match':['Solr Admin', 'app_config.solr_path'],
                                'title':'Apache Solr'
                              },
                               '/webmin':{
                                'app':'WEBMIN',
                                'match':['login to the Webmin server', 'Login to Webmin'],
                                'title':'Webmin Management Portal'
                              },
                               '/prometheus/config':{
                                'app':'PROMETHEUS',
                                'match':['/prometheus/targets'],
                                'title':'Prometheus Monitoring'
                              },
                               '/artifactory/webapp':{
                                'app':'JFROG_ARTIFACTORY',
                                'match':['artifactory.ui', 'artifactory_views'],
                                'title':'Artifactory'
                              },
                              '/artifactory/libs-release':{
                                'app':'JFROG_LIB_RELEASE',
                                'match':['Index of libs-release/'],
                                'title':'Artifactory Directory Exposure'
                              },
                              '/admin/env':{
                                'app':'ADMIN_ENV',
                                'match':['server.ports'],
                                'title':'Admin Env'
                              },
                              '/node':{
                                'app':'HADOOP_RM',
                                'match':['Hadoop Version','List of Applications','Hadoop:*'],
                                'title':'Hadoop Resource Manager'
                              },
                              '/ui':{
                                'app':'HASHICORP_CONSUL',
                                'match':['Consul by HashiCorp', 'consul-ui/config/environment'],
                                'title':'HashiCorp Consul'
                              },
                              '/api/users':{
                                'app':'DJANGO_API_USERS',
                                'match':['is_staff'],
                                'title':'Django REST Users List'
                              },
                              '/Reports/Pages/Folder.aspx':{
                                'app':'MS_SQL_REPORTING',
                                'match':['Report Manager'],
                                'title':'MSSQL Reporting Manager'
                              },
                              '/v2/_catalog':{
                                'app':'DOCKER_REGISTRY_LIST',
                                'match':['"repositories":'],
                                'title':'Docker Registry List'
                              },
                              '/graph':{
                                'app':'PROMETHEUS',
                                'match':['Prometheus Time Series Collection and Processing Server'],
                                'title':'Prometheus Server'
                              },
                              '/console':{
                                'app':'WERKZEUG',
                                'match':['<h1>Interactive Console</h1>'],
                                'title':'Werkzeug Console'
                              },
                              '/debug/pprof/':{
                                'app':'PPROF',
                                'match':['Types of profiles available'],
                                'title':'PProf'
                              },
                              '/examples/jsp/snp/snoop.jsp':{
                                'app':'SNOOP_JSP',
                                'match':['Authorization scheme','Servlet path:','Remote host'],
                                'title':'Snoop JSP'
                              },
                              '/jmx-console':{
                                'app':'JMX_CONSOLE',
                                'match':['JBoss JMX Management Console'],
                                'title':'JMX Console'
                              },
                              '/+CSCOE+/logon.html':{
                                'app':'CISCO_ASA',
                                'match':['<title>SSL VPN Service</title>'],
                                'title':'Cisco ASA'
                              },
                              '/global-protect/login.esp':{
                                'app':'PAN_GP',
                                'match':['GlobalProtect Portal'],
                                'title':'PAN GlobalProtect'
                              },
                              '/php/login.php':{
                                'app':'PANOS_PANEL',
                                'match':['BEGIN PAN_FORM_CONTENT'],
                                'title':'Palo Alto Panel (PanOS)'
                              },
                              '/__clockwork/app':{
                                'app':'CLOCKWORK',
                                'match':['<title>Clockwork</title>'],
                                'title':'Clockwork'
                              },
                              '/jolokia/version':{
                                'app':'JOLOKIA1',
                                'match':['dispatcherClasses'],
                                'title':'Jolokia'
                              },
                              '/jolokia/list':{
                                'app':'JOLOKIA2',
                                'match':['jdk.management.jfr', 'FlightRecorder'],
                                'title':'Jolokia'
                              },
                              '/login':{
                                  'app':'REDASH',
                                  'match':['Login to Redash'],
                                  'title':'Redash'
                              },
                              '/web.config':{
                                'app':'ASPNET_CONFIG',
                                'match':['system.webServer'],
                                'title':'ASP.NET Config'
                              },
                              '/api/jsonws/invoke':{
                                'app':'LifeRay JSON API',
                                'match':['"_type":"jsonws"'],
                                'title':'LifeRay'
                              },
                              '/adminer.php':{
                                'app':'Adminer PHP',
                                'match':['adminer.org'],
                                'title':'Adminer PHP'
                              },
                              '/struts/webconsole.html':{
                                'app':'OGNL_CONSOLE',
                                'match':['OGNL console'],
                                'title':'OGNL Console'
                              },
                              '/composer.json':{
                                'app':'COMPOSER_JSON',
                                'match':['"require": {'],
                                'title':'Composer'
                              },
                                '/jasperserver/login.html?error=1':{
                                  'app':'JASPERSOFT',
                                  'match':['TIBCO Jaspersoft: Login', 'Could not login to JasperReports Server',
                                            'About TIBCO JasperReports Server'],
                                  'title':'Jaspersoft'
                                },
                                '/users/sign_in':{
                                  'app':'GITLAB1',
                                  'match':['Register for GitLab'],
                                  'title':'Gitlab'
                                },
                                '/users/sign_up':{
                                  'app':'GITLAB2',
                                  'match':['Register for GitLab'],
                                  'title':'Gitlab'
                                },
                                '/explore':{
                                  'app':'GITLAB3',
                                  'match':['Register for GitLab'],
                                  'title':'Gitlab'
                                },
    }

    self.intensity = 3
    
  def check_rule(self, ip, port, values, conf):
    c = ConfParser(conf)
    t = Triage()
    p = ScanParser(port, values)
    
    domain  = p.get_domain()
    module  = p.get_module()
    
    if 'http' in module:
      for uri, values in self.rule_match_string.items():
        app_name = values['app']
        app_title = values['title']
  
        resp = t.http_request(ip, port, uri=uri)

        if resp is not None:
          for match in values['match']:
            if match in resp.text:
              self.rule_details = 'Exposed {} at {}'.format(app_title, uri)
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
              break
              
    return
