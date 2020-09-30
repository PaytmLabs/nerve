from core.security import session_required
from flask import Blueprint, render_template
from core.redis import rds


assets = Blueprint('assets', __name__,
                    template_folder='templates')

@assets.route('/assets')
@session_required
def view_assets():
  data = rds.get_inventory_data()
  return render_template('assets.html', data=data)