import copy
import config

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger

from flask import (
  Blueprint, 
  render_template, 
  flash, 
  request, 
  redirect
)

qs = Blueprint('qs', __name__,
                template_folder='templates')

@qs.route('/qs', methods=['GET', 'POST'])
@session_required
def view_qs():
  if request.method == 'POST':
    register = Register()
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
 