from core.security import session_required
from core.register import Register
from core.parser   import SchemaParser

from flask import Blueprint, request

scan = Blueprint('scan', __name__,
                  template_folder='templates')

@scan.route('/scan',  methods=["POST"])
@session_required
def view_scan():
  register = Register()
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
