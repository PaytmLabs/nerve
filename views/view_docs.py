from core.security import session_required
from flask import Blueprint, render_template

documentation = Blueprint('documentation', __name__,
                         template_folder='templates')

@documentation.route('/documentation')
@session_required
def view_doc():
  return render_template('documentation.html')
