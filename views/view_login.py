from core.utils import Utils
from core.redis import rds
from core.security import verify_password

from flask import (
  Blueprint, 
  render_template, 
  request,
  session,
  redirect
)

login = Blueprint('login', __name__,
                  template_folder='templates')

@login.route('/login', methods=['GET', 'POST'])
def view_login():
  utils = Utils()
  msg = ''
  
  if request.method == 'POST':
    username = request.form.get('username', None)
    password = request.form.get('password', None)
    
    if rds.is_ip_blocked(request.remote_addr):
      return render_template('login.html', err='Your IP has been blocked.')
    
    if verify_password(username, password):
      session['session'] = username
      return redirect('/')
    else:
      return render_template('login.html', err='Incorrect username or password. \
                                                After 5 attempts, you will get blocked.')
  
  if not utils.is_version_latest():
    msg = 'New Version is Available'
  
  return render_template('login.html', msg=msg)