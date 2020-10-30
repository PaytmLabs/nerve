import requests

from core.utils     import Utils
from core.security  import auth

from flask_restful  import Resource
from flask import request

class Update(Resource):
  @auth.login_required
  def get(self, component=None):  
    utils = Utils()
    if not component:
      return {'status':'Component is missing'}, 400
    
    if component == 'platform':
      if not utils.is_version_latest:
        return {'status':'updates are available'}
      else:
        return {'status':'system is up to date'}  
    
    
    return {'status':'unsupported action'}, 400