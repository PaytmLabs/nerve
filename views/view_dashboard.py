from core.security import session_required
from core.utils import Utils, Charts
from core.redis import rds

from flask import Blueprint, render_template

dashboard = Blueprint('dashboard', __name__,
                      template_folder='templates')

@dashboard.route('/dashboard')
@session_required
def view_dashboard():
  chart = Charts()
  networks = []
  domains  = []
  
  hosts = rds.get_topology()
  cfg   = rds.get_scan_config()
  vulns = rds.get_vuln_data()
 
  total_potential_vulns = 0
  total_confirmed_vulns = 0
  for v,data in vulns.items():
    if data['rule_sev'] == 6:
      total_potential_vulns += 1
    else:
      total_confirmed_vulns += 1
 
  if cfg:
    networks = cfg['targets']['networks']
    domains = cfg['targets']['domains']
  
  return render_template('dashboard.html', 
                         hosts=hosts,
                         networks=networks,
                         last_scan=rds.get_last_scan(),
                         scan_count=rds.get_scan_count(),
                         domains=domains,
                         vulns=vulns,
                         total_potential_vulns=total_potential_vulns,
                         total_confirmed_vulns=total_confirmed_vulns,
                         chart=chart.make_doughnut(vulns),
                         radar=chart.make_radar(vulns))
