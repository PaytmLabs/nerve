from core.security import session_required
from core.utils import Utils, Charts
from core.redis import rds

from flask import Blueprint, render_template

topology = Blueprint('topology', __name__,
                    template_folder='templates')

@topology.route('/topology')
@session_required
def view_topologys():
  data  = rds.get_topology()
  vulns = rds.get_vuln_data()
  return render_template('topology.html', data=data, vulns=vulns)

