from core.security import session_required
from flask import Blueprint, render_template
from core.redis import rds

vulns = Blueprint('vulnerabilities', __name__,
                    template_folder='templates')

@vulns.route('/vulnerabilities')
@session_required
def view_vulns():
  data = rds.get_vuln_data()
  return render_template('vulnerabilities.html', data=data)
