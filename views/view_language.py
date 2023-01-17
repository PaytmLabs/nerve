from core.security import session_required
from core.redis    import rds
from core.logging  import logger

from flask import Blueprint, request
 
language = Blueprint('language', __name__,
                   template_folder='templates')
 
@language.route('/language',  methods=["POST"])
@session_required
def change_language():
  language = request.data
  logger.debug('Se obtiene el request: {}'.format(language))
  rds.change_language(language)
  return 

