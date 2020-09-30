from core.redis import rds
from core.utils import Utils
from core.security import session_required
from core.mailer  import send_email

from flask import Blueprint, render_template, request

settings = Blueprint('settings', __name__,
                     template_folder='templates')

@settings.route('/settings', methods=['GET', 'POST', 'DELETE'])
@session_required
def view_settings():
  utils = Utils()
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
