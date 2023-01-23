from core.security import session_required

from flask import (
  Blueprint,   
  redirect,
  flash,
  session
)
from flask_babel import _

logout = Blueprint('logout', __name__,
                    template_folder='templates')

@logout.route('/logout')
@session_required
def view_logout():
  if session.get('session'):
    session.pop('session')

  flash(_('Logged out successfully'), 'success')

  return redirect('/login')
