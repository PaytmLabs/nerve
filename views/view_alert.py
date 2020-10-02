from core.redis import rds
from core.security import session_required

from flask import (
  Blueprint,
  render_template,
  flash,
  redirect
)

alert = Blueprint('alert', __name__,
                      template_folder='templates')

@alert.route('/alert/view/<alert_id>')
@session_required
def view_alert(alert_id):
  vuln = rds.get_vuln_by_id(alert_id)
  if not vuln:
    flash('Could not display alert.',  'error')
    return redirect('/vulnerabilities')
  
  return render_template('alert.html', vuln={'key':alert_id,'data':vuln})
  

@alert.route('/alert/resolve/<alert_id>')
@session_required
def view_resolve_alert(alert_id):
  if not rds.get_vuln_by_id(alert_id):
    flash('Could not resolve alert.',  'error')
    return redirect('/vulnerabilities')
  
  rds.delete(alert_id)
  flash('Resolved alert successfully.',  'success')
  return redirect('/vulnerabilities')