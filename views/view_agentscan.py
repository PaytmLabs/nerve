import copy
import config

from core.security import session_required
from core.redis import rds
from core.parser import SchemaParser
from core.register  import Register
from core.logging   import logger
from core.command_sender import CommandSender

from flask import (
  Blueprint,
  render_template,
  flash,
  request,
  redirect
)

agentscan = Blueprint('agentscan', __name__,
                template_folder='templates')

@agentscan.route('/agentscan', methods=['GET','POST'])
@session_required
def view_agentscan():
  if request.method == 'POST':
    register = Register()
    ip = request.values.get('ip')
    username_ssh = request.values.get('username_ssh')
    password_ssh = request.values.get('password_ssh')
    how = request.values.get('how')

    if ip:
      logger.info("Sending preliminar SSH commands..")
      real_ip = ''
      try:
        CommandSender(ip, username_ssh, password_ssh, how)
        real_ip = ip
        ip = '10.0.2.2'
      except Exception as e:
        errore = 'Failed to execute preliminar SSH commands: '+ str(e)
        logger.error(errore)
        logger.exception(e)
        flash(errore, 'error')
      else:
        scan = copy.deepcopy(config.DEFAULT_SCAN)
        scan['type_ie'] = 'internal'
        scan['how'] = how
        scan['real_ip'] = real_ip 
        scan['username_ssh'] = username_ssh
        scan['password_ssh'] = password_ssh
        scan['targets']['networks'].append(ip)
        schema = SchemaParser(scan, request)
        vfd, msg, scan = schema.verify()

        logger.info(str(scan))

        if vfd:
          res, code, msg = register.scan(scan)
          if res:
            logger.info('A scan was initiated')
            flash('Assessment started.', 'success')
            return redirect('/agentscan')
          else:
            flash(msg, 'error')

        else:
          flash(msg, 'error')

  return render_template('agentscan.html')
