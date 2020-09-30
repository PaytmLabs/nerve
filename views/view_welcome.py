from core.security import session_required
from flask import Blueprint, render_template
from core.redis import rds

welcome = Blueprint('welcome', __name__,
                    template_folder='templates')

@welcome.route('/welcome')
@session_required
def view_welcome():
  return render_template('welcome.html')