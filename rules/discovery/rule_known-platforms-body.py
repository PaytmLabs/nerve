from core.redis   import rds
from core.triage  import Triage
from core.parser  import ScanParser
from db.db_paths  import COMMON_LOGIN_PATHS

class Rule:
  def __init__(self):
    self.rule = 'DSC_A4F1'
    self.rule_severity = 1
    self.rule_description = 'This rule checks for the exposure of Web Panels'
    self.rule_confirm = 'Identified a Known Web Panel'
    self.rule_details = ''
    self.rule_mitigation = '''Identify whether the application in question is supposed to be exposed to the network.'''
    self.rule_doc_roots = COMMON_LOGIN_PATHS
    self.rule_match_string  = {
                    'Generic Panel':{
                      'app':'GENERIC',
                      'match':['Sign In', 'Login', 'Forgot Password', 'Authenticate', 'input type="password"'],
                      'title':'Login Page'
                    },
                    'Guest Panel':{
                      'app':'GUEST',
                      'match':['Anonymous Login', 'anonymous login', 'guest login'],
                      'title':'Guest Panel'
                    },
                    'Django Admin':{
                      'app':'DJANGO',
                      'match': ['Django site admin'],
                      'title': 'Python Web Framework'
                    }, 
                    'RabbitMQ':{
                      'app':'RABBITMQ',
                      'match': ['RabbitMQ Management'],
                      'title': 'Message Queue'
                    },
                    'Kibana':{
                      'app':'KIBANA',
                      'match':['kibanaWelcomeView'],
                      'title':'Analytics'
                    },
                    'ElasticSearch':{
                      'app':'ELASTICSEARCH',
                      'match':['You Know, for Search'],
                      'title':'Search Database'
                    },
                    'Grafana':{
                      'app':'GRAFANA',
                      'match':['Loading Grafana', 'grafana-app', 'grafana.dark.css'],
                      'title':'Graph Platform'
                    },
                    'Django Debug':{
                      'app':'DJANG_DEBUG',
                      'match':['DisallowedHost at /', 'WSGIServer'],
                      'title':'Web Framework Debug Page'
                    },
                    'SonarQube':{
                      'app':'SONARQUBE',
                      'match':['SonarQube'],
                      'title':'Web Assessment Tool'
                    },
                    'PHP LDAP Admin':{
                      'app':'PHP_LDAP_ADMIN',
                      'match': ['Welcome to phpMyAdmin'],
                      'title':'LDAP Administration'
                    },
                    'phpMyAdmin':{
                      'app':'PHPMYADMIN',
                      'match':['phpMyAdmin'],
                      'title':'MySQL Administration'
                    },
                    'PHP Info Page':{
                      'app':'PHP_INFO',
                      'match':['phpinfo', 'PHP License'],
                      'title':'Default PHP Page'
                    },
                    'Open Panel':{
                      'app':'OPEN_PANEL',
                      'match':['sign in as guest', 'Sign in as Guest','Logged in as', 'Signed in as', 'Authenticated as'],
                      'title':'Open Panel'
                    },
                    'Cacti':{
                      'app':'CACTI',
                      'match':['Login to Cacti'],
                      'title':'Monitoring System'
                    },
                    'Ganglia':{
                      'app':'GANGLIA',
                      'match':['Ganglia'],
                      'title':'Monitoring System'
                    },
                    'MailDev':{
                      'app':'MAILDEV',
                      'match': ['mailDevApp', 'for viewing and testing emails during development'],
                      'title':'Mail App'
                    },
                    'MediaWiki':{
                      'app':'MEDIAWIKI',
                      'match':['Powered By MediaWiki', '<meta name="generator" content="MediaWiki'],
                      'title':'Wiki Software'
                    },
                    'MongoDB':{
                      'app':'MONGODB',
                      'match':['<a href="/buildInfo?text=1" title="get version #, etc.', '<title>mongod'],
                      'title':'MongoDB Administration'
                    },
                    'Plesk':{
                      'app':'PLESK',
                      'match':['Default PLESK Page', 'def_plesk_logo'],
                      'title':'Plesk'
                    },
                    'PmWiki':{
                      'app':'PMWIKI',
                      'match':['<!--PageLeftFmt-->', 'commentout-pmwikiorg'],
                      'title':'PmWiki'
                    },
                    'DokuWiki':{
                      'app':'DOKUWIKI',
                      'match':['powered by DokuWiki', 'content="DokuWiki Release'],
                      'title':'DokuWiki'
                    },
                    'cPanel':{ 
                      'app':'CPANEL',
                      'match':['cPanel&reg;', 'sys_cpanel/images/powered_by.gif'],
                      'title':'cPanel'
                    },
                    'Tomcat Manager':{
                      'app':'TOMCAT_MANAGER',
                      'match':['setup Tomcat successfully', 'CATALINA_HOME'],
                      'title':'Tomcat Manager'
                    },
                    'Spring Boot':{
                      'app':'SPRING_BOOT',
                      'match':['Spring Boot Admin', 'spring-boot-logo'],
                      'title':'Spring Boot Panel'
                    },
                    'Aerospike':{
                      'app':'AEROSPIKE',
                      'match':['Multicluster View is supported', 'Update interval should be non zero'],
                      'title':'Aerospike Panel'
                    },
                    'Selenium Grid Node':{
                      'app':'SELENIUM_GIRD_NODE',
                      'match':['perhaps you are looking for the Selenium Grid Node'],
                      'title':'Selenium Grid Node'
                    },
                    'Cyberoam':{
                      'app':'CYBEROAM_SSL_VPN',
                      'match':['Cyberoam SSL VPN Portal!', 'www.cyberoam.com'],
                      'title':'Cyberoam SSL VPN Interface'
                    },
                    'Webmin':{
                      'app':'WEBMIN',
                      'match':['login to the Webmin server', 'Login to Webmin', 'wbm-webmin'],
                      'title':'Webmin Management Portal'
                    },
                    'Graylog':{
                      'app':'GRAYLOG',
                      'match':['Graylog Web Interface'],
                      'title':'Graylog Web Interface'
                    },
                    'Solr':{
                      'app':'APACHE_SOLR',
                      'match':['app_config.solr_path', 'Solr Admin', 'SolrCore Initialization'],
                      'title':'Apache Solr'
                    },
                    'Prometheus':{
                      'app':'PROMETHEUS',
                      'match':['/prometheus/targets'],
                      'title':'Prometheus Monitoring'
                    },
                     'Nessus':{
                      'app':'NESSUS',
                      'match':['nesssus6.js', 'nessus6.css', '<title>Nessus</title>'],
                      'title':'Nessus VA Console'
                    },
                    'Jenkins':{
                      'app':'JENKINS',
                      'match':['Sign in [Jenkins]', 'Welcome to Jenkins'],
                      'title':'Jenkins'
                    },
                    'Polycom':{
                      'app':'POLYCOM',
                      'match':['- Polycom'],
                      'title':'Polycom'
                    },
                    'KongAPI':{
                       'app':'KONG_API',
                       'match':['prng_seeds'],
                       'title':'Kong API'
                     },
                    'SAP':{
                       'app':'SAP',
                       'match':['sap-system-login-basic_auth', 'sap-system-login'],
                       'title':'SAP'
                     },
                    'OpenVAS':{
                      'app':'OPENVAS',
                      'match':['Greenbone Security Manager'],
                      'title':'OpenVAS Panel'
                    },
                    'DMS Panel':{
                      'app':'DMS',
                      'match':['<title>dmspanel</title>'],
                      'title':'DMS Panel'
                    },
                    'Kubernetes Dashboard':{
                      'app':'K8S_DASHBOARD',
                      'match':['Kubernetes Dashboard'],
                      'title':'Kubernetes Dashboard'
                    },
                    'Netweaver Panel':{
                      'app':'NETWEAVER',
                      'match':['data-sap-ls-system-userAgent', 'sap-system-login'],
                      'title':'Netweaver Panel'
                    },
                    'DMS Panel':{
                      'app':'DMS',
                      'match':['<title>dmspanel</title>'],
                      'title':'DMS Panel'
                    },
                    'F5 BIGIP':{
                      'app':'F5_BIGIP',
                      'match':['<title>BIG-IP', 'BIG-IP-F5'],
                      'title':'F5 BIG-IP'
                    },
                    'Pritunl':{
                      'app':'PRITUNL',
                      'match':['<title>Pritunl</title>'],
                      'title':'Distributed VPN'
                    },
                    'Adobe AEM':{
                      'app':'ADOBE_AEM',
                      'match':['/etc.clientlibs/', 'etc.clientlibs/'],
                      'title':'Adobe AEM'
                    },
                    'Github':{
                      'app':'GITHUB',
                      'match':['GitHub · Enterprise'],
                      'title':'GitHub Enterprise'
                    }
                  }

    self.intensity = 3

  def check_rule(self, ip, port, values, conf):
    t = Triage()
    p = ScanParser(port, values)
    
    domain = p.get_domain()
    module = p.get_module()
    
    if 'http' not in module:
      return
    
    for uri in self.rule_doc_roots:
      resp = t.http_request(ip, port, uri=uri)
      
      for _, val in self.rule_match_string.items():
        app_title = val['title']
        if resp:
          for i in val['match']:
            if i in resp.text:
              self.rule_details = '{} Exposed at {}'.format(app_title, resp.url)
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
              break
    
    return
              