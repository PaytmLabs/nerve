from core.redis     import rds
from core.parser    import SchemaParser
from core.register  import Register
from core.security  import auth

from flask_restful  import Resource
from flask import request

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

  @auth.login_required   
  def put(self, action=None):
    if action == 'reset':
      rds.clear_session()
      return {'status':'flushed scan state'}
    
    return {'status':'unsupported action'}, 400
  
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
      return {'status':'Malformed Scan Data'}, 400
    
    res, code, msg = register.scan(scan)
    
    return {'status': msg}, code
