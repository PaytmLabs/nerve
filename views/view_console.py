from core.security import session_required
from flask import Blueprint, render_template

console = Blueprint('console', __name__,
                    template_folder='templates')

@console.route('/console')
@session_required
def view_console():
  return render_template('console.html')
