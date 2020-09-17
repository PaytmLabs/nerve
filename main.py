import time
import json
import config
import os
import threading
import copy

from flask import (
  Flask, 
  request, 
  session, 
  redirect, 
  render_template, 
  make_response, 
  send_from_directory,
  flash
  )

from flask_httpauth import HTTPBasicAuth
from flask_restful  import Resource, Api
from werkzeug.security import (
  generate_password_hash, 
  check_password_hash
)
from functools      import wraps
from core.logging   import logger
from core.register  import Register
from core.redis     import rds
from core.parser    import SchemaParser
from core.utils     import Utils, Charts
from core.mailer    import send_email
from core.reports   import (
  generate_html, 
  generate_csv, 
  generate_txt
)
from bin.scanner    import scanner
from bin.attacker   import attacker
from bin.scheduler  import scheduler

auth = HTTPBasicAuth()
app = Flask(__name__)
app.config.update(
  SESSION_COOKIE_SAMESITE='Strict',
)
app.secret_key = os.urandom(24)
api = Api(app)
register = Register()
utils = Utils()

def session_required(function_to_protect):
  @wraps(function_to_protect)
  def wrapper(*args, **kwargs):
    if not session.get('session'):
      return redirect('/login', 307)
    
    return function_to_protect(*args, **kwargs)
  return wrapper

def run_workers():
  thread = threading.Thread(target=scanner)
  thread.name = "scanner"
  thread.daemon = True
  thread.start()
  
  thread = threading.Thread(target=attacker)
  thread.name = "attacker"
  thread.daemon = True
  thread.start()
  
  thread = threading.Thread(target=scheduler)
  thread.name = "scheduler"
  thread.daemon = True
  thread.start()
  
@auth.verify_password
def verify_password(username, password):
  if rds.is_ip_blocked(request.remote_addr):
    return False
  
  if username == config.WEB_USER and \
    check_password_hash(generate_password_hash(config.WEB_PASSW), password):
    return True
  
  rds.log_attempt(request.remote_addr)
  return False

@app.route('/')
@session_required
def index():
  # We set a cookie for "First time users" to show them the welcome message once.
  if 'toggle_welcome' not in request.cookies:
    resp = make_response(render_template('welcome.html'))
    resp.set_cookie('toggle_welcome', 'true')
    return resp
  
  return redirect('/dashboard')

@app.route('/settings', methods=['GET', 'POST', 'DELETE'])
@session_required
def settings():
  email_settings = rds.get_email_settings()
  slack_settings = rds.get_slack_settings()
  
  if request.method == 'POST':
    u_settings = request.get_json()
    
    if u_settings and isinstance(u_settings, dict):
      if 'email' in u_settings:
        msg, code = send_email(u_settings['email'])
        
      elif 'slack' in u_settings:
        hook = u_settings['slack'].get('hook', None)
        if utils.is_string_url(hook):
          rds.store('p_settings_slack', hook)
          code, msg = 200, 'Saved Slack Setting'
        else:
          code, msg = 400, 'Slack hook must be a URL'

      else:
        code, msg = 400, 'Error Occurred'
      
      return  {'status': msg }, code
        
  elif request.method == 'DELETE':
    u_settings = request.get_json()
    settings = u_settings.get('settings', None)
    if settings == 'email':
      rds.delete('p_settings_email')
      code, msg = 200, 'Deleted Email Settings'
    elif settings == 'slack':
      rds.delete('p_settings_slack')
      code, msg = 200, 'Deleted Slack Settings'
    else:
      code, msg = 400, 'Error Occurred'
      
    return  {'status': msg}, code
  
  return render_template('settings.html', 
                         email=email_settings, 
                         slack=slack_settings)

@app.route('/dashboard')
@session_required
def dashboard():
  chart = Charts()
  networks = []
  domains  = []
  hosts = rds.get_topology()
  cfg   = rds.get_scan_config()
  vulns = rds.get_vuln_data()
  if cfg:
    networks = cfg['targets']['networks']
    domains = cfg['targets']['domains']
  
  return render_template('dashboard.html', 
                         hosts=hosts,
                         networks=networks,
                         last_scan=rds.get_last_scan(),
                         scan_count=rds.get_scan_count(),
                         domains=domains,
                         vulns=vulns,
                         chart=chart.make_doughnut(vulns),
                         radar=chart.make_radar(vulns))

@app.route('/reports')
@session_required
def reports():
  return render_template('reports.html')

@app.route('/documentation')
@session_required
def documentation():
  return render_template('documentation.html')

@app.route('/qs', methods=['GET', 'POST'])
@session_required
def quickstart():
  if request.method == 'POST':
    # In Quickstart, we only take the network provided by the user as input
    # The rest is as defined in config.py
    network = request.values.get('network')  
    
    if network:
      scan = copy.deepcopy(config.DEFAULT_SCAN)
      scan['targets']['networks'].append(network)
      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()
      
      if vfd:
        res, code, msg = register.scan(scan)
        if res:
          logger.info('A scan was initiated')
          flash('Assessment started.', 'success')
          return redirect('/qs')
        else:
          flash(msg, 'error')
    
      else:
        flash(msg, 'error')
      
  return render_template('quickstart.html')

@app.route('/scan', methods=["POST"])
@session_required
def start_scan():
  scan = request.get_json()
  
  if scan and isinstance(scan, dict):
    schema = SchemaParser(scan, request)
    vfd, msg, scan = schema.verify()

    if not vfd:
      return {'status':'Error: ' + msg }, 400
  else:
    return {'status':'Malformed Scan Data'}, 400
  
  res, code, msg = register.scan(scan)

  return {'status': msg}, code

@app.route('/topology')
@session_required
def topology():
  data = rds.get_topology()
  vulns = rds.get_vuln_data()
  return render_template('topology.html', data=data, vulns=vulns)

@app.route('/startover')
@session_required
def startover():
  rds.clear_session()
  flash('Rolled back successfully', 'success')
  return redirect('/', 301)

@app.route('/assessment')
@session_required
def assessment():
  return render_template('assessment.html')

@app.route('/vulnerabilities')
@session_required
def vulnerabilities():
  data = rds.get_vuln_data()
  return render_template('vulnerabilities.html', data=data)

@app.route('/assets')
@session_required
def assets():
  data = rds.get_inventory_data()
  return render_template('assets.html', data=data)

@app.route('/welcome')
@session_required
def welcome():
  return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    
    if rds.is_ip_blocked(request.remote_addr):
      return render_template('login.html', err='Your IP has been blocked.')
    
    if verify_password(username, password):
      session['session'] = username
      return redirect('/')
    else:
      return render_template('login.html', err='Incorrect username or password.')
  
  return render_template('login.html')
  
@app.route('/logout')
def logout():
  if session.get('session'):
    session.pop('session')

  flash('Logged out successfully', 'success')
  
  return render_template('login.html')

@app.route('/log')
@session_required
def log():
  return render_template('console.html')
  
@app.route('/download/<file>')
@session_required
def download(file):
  if not file:
    return {'status':'file is missing'}, 400
  
  if file == 'server_log':
    response = send_from_directory(directory='logs', 
                                    filename=config.WEB_LOG,
                                    as_attachment=True,
                                    cache_timeout=0)
    return response
  
  else:
    data = rds.get_vuln_data()
    conf = rds.get_scan_config()
    
    if not data and not conf:
      flash('There is no data in the system for report generation', 'error')
      return redirect('/reports')
    
    if file == 'report_html':  
      report_file = generate_html(data, conf)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    
    elif file == 'report_txt':
      report_file = generate_txt(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    elif file == 'report_csv':
      report_file = generate_csv(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response

@app.route('/stream')
@session_required
def stream():
  def generate():
    with open('logs/nerve.log') as f:
      while True:
        yield f.read()
        time.sleep(1)
  
  return app.response_class(generate(), mimetype='text/plain')

class Health(Resource):
  def get(self):
    return {'status': 'OK'}

class Scan(Resource):
  @auth.login_required
  def get(self, action=None):  
    if not action:
      return {'status':'action type is missing'}, 400
    
    if action == 'status':
      state = rds.get_session_state()
      data = rds.get_vuln_data()
      cfg = rds.get_scan_config()
      
      if not state:
        state = 'idle'
      
      return {'status':state, 'vulnerabilities':data, 'scan_config':cfg}
    
    return {'status':'unsupported action'}, 400
    
  def put(self, action=None):
    if action == 'reset':
      rds.clear_session()
      return {'status':'flushed scan state'}
    
    return {'status':'unsupported action'}, 400
  
  @auth.login_required
  def post(self, action=None):
    scan = request.get_json()
    if scan and isinstance(scan, dict):  
      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()
      if not vfd:
        return {'status':'Error: ' + msg }, 400
    else:
      return {'status':'Malformed Scan Data'}, 400
    
    res, code, msg = register.scan(scan)
    
    return {'status': msg}, code

  @auth.login_required
  def delete(self):
    rds.flushdb()
    return {'status':'OK'}
    
api.add_resource(Health, 
                 '/health')

api.add_resource(Scan, 
                 '/api/scan',
                 '/api/scan/<string:action>'
                 )



# Context Processors
@app.context_processor
def status():
  progress = rds.get_scan_progress()
  session_state = rds.get_session_state()
  status = 'Ready'
  if session_state == 'created':
    status = 'Initializing...'
  elif session_state == 'running':
    if progress: 
      status = 'Scanning... [QUEUE:{}]'.format(progress)
    else:
      status = 'Busy...'

  return dict(status=status)

@app.context_processor
def show_version():
  return dict(version=config.VERSION)

# Context Processors
@app.context_processor
def show_frequency():
  config = rds.get_scan_config()
  scan_frequency = None
  if config:
    scan_frequency = config['config']['frequency']
  return dict(frequency=scan_frequency)
    
  
# Set Security Headers
@app.after_request
def add_security_headers(resp):
  if config.WEB_SECURITY:
    resp.headers['Content-Security-Policy'] = config.WEB_SEC_HEADERS['CSP']
    resp.headers['X-Content-Type-Options'] = config.WEB_SEC_HEADERS['CTO']
    resp.headers['X-XSS-Protection'] = config.WEB_SEC_HEADERS['XSS']
    resp.headers['X-Frame-Options'] = config.WEB_SEC_HEADERS['XFO']
    resp.headers['Referrer-Policy'] = config.WEB_SEC_HEADERS['RP']
    resp.headers['Server'] = config.WEB_SEC_HEADERS['Server']
    return resp  
  
if __name__ == '__main__':  
  rds.initialize()
  run_workers()
  app.run(debug = config.WEB_DEBUG, 
          host  = config.WEB_HOST, 
          port  = config.WEB_PORT,
          threaded=True,
          use_evalex=False)
