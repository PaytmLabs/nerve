from core.redis     import rds
from core.parser    import SchemaParser
from core.register  import Register
from core.security  import auth
from core.utils     import Utils
from core.logging   import logger

from flask_restful  import Resource
from flask          import request
from flask_babel    import _

class Scan(Resource):
  @auth.login_required
  def get(self, action=None):  
    if not action:
      return {'status':_('action type is missing')}, 400
    
    if action == 'status':
      state = rds.get_session_state()
      data = rds.get_vuln_data()
      # Might not be accurate, since it can correspond to the next queued scan.
      cfg = rds.get_next_scan_config()
      # Format datetime to time for json format
      cfg['config']['schedule_date'] = Utils.json_serial(cfg['config']['schedule_date'])
      
      if not state:
        state = 'idle'
      
      return {'status':state, 'vulnerabilities':data, 'scan_config':cfg}
    
    return {'status':_('unsupported action')}, 400

  @auth.login_required   
  def put(self, action=None):
    if action == 'reset':
      rds.clear_session()
      return {'status':_('flushed scan state')}
    
    return {'status':_('unsupported action')}, 400
  
  @auth.login_required
  def post(self, action=None):
    scan = request.get_json()
    register = Register()
    
    if scan and isinstance(scan, dict):  
      schema = SchemaParser(scan, request)
      vfd, msg, scan = schema.verify()

      if not vfd:
        return {'status':'Error: ' + msg }, 400
    else:
      return {'status':_('Malformed Scan Data')}, 400
    
    res, code, msg = register.scan(scan)
    
    return {'status': msg}, code
