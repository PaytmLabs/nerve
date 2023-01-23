from core.redis import rds
from core.security import session_required

from flask import Blueprint, flash, redirect
from flask_babel import _

startover = Blueprint('startover', __name__,
                       template_folder='templates')

@startover.route('/startover')
@session_required
def view_startover():
  rds.clear_session()
  flash(_('Rolled back successfully'), 'success')
  return redirect('/dashboard', 301)
