from core.security import session_required
from flask import Blueprint, render_template
from core.redis import rds

vulns = Blueprint('vulnerabilities', __name__,
                   template_folder='templates')

@vulns.route('/vulnerabilities')
@session_required
def view_vulns():
  data = rds.get_vuln_data()
  if data:
    data = {k: v for k, v in sorted(data.items(), 
            key=lambda item: item[1]['rule_sev'], 
            reverse=True)}
  return render_template('vulnerabilities.html', data=data)
