import os

# Logger Configuration
LOG_LEVEL = 'INFO'

# Webserver Configuration
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WEB_DEBUG = False
WEB_USER = os.environ.get('username', 'admin')
WEB_PASSW = os.environ.get('password', 'admin')
WEB_LOG = 'nerve.log'

# Web Security
# Setting this to True will return all responses with security headers.
WEB_SECURITY = True
WEB_SEC_HEADERS = {
  'CSP':'default-src \'self\' \'unsafe-inline\'; object-src \'none\'; img-src \'self\' data:',
  'CTO':'nosniff',
  'XSS':'1; mode=block',
  'XFO':'DENY',
  'RP':'no-referrer',
  'Server':'NERVE'
}

# Maximum allowed attempts before banning the remote origin
MAX_LOGIN_ATTEMPTS = 5

# Redis Configuration
# This should not be set to anything else except localhost unless you want to do a multi-node deployment.
RDS_HOST = '127.0.0.1'
RDS_PORT = 6379
RDS_PASSW = None

# Scan Configuration
USER_AGENT = 'NERVE'

# Default scan configuration
# This will be used in the "Quick Start" scan. 
DEFAULT_SCAN = {
  'targets':{
    'networks':[],
    'excluded_networks':[],
    'domains':[]
  },
  'config':{
    'name':'Default',
    'description':'My Default Scan',
    'engineer':'John Doe',
    'allow_aggressive':3,
    'allow_dos':False,
    'allow_bf':False,
    'allow_internet':True,
    'dictionary':{
      'usernames':[],
      'passwords':[]
    },
    'scan_opts':{
      'interface':None,
      'max_ports':100,
      'custom_ports':[],
      'parallel_scan':50,
      'parallel_attack':30,
    },
    'post_event':{
      'webhook':None
    },
    'frequency':'once'
  }
}
