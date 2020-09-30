from core.security import session_required
from flask import (
  Blueprint, 
  request, 
  redirect,
  make_response,
  render_template
)

index = Blueprint('index', __name__,
                   template_folder='templates')

@index.route('/')
@session_required
def view_index():
  if 'toggle_welcome' not in request.cookies:
    resp = make_response(render_template('welcome.html'))
    resp.set_cookie('toggle_welcome', 'true')
    return resp
  
  return redirect('/dashboard')
