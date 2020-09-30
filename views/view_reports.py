from core.security import session_required
from flask import Blueprint, render_template

reports = Blueprint('reports', __name__,
                    template_folder='templates')

@reports.route('/reports')
@session_required
def view_reports():
  return render_template('reports.html')
