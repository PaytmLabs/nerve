import config

from core.redis import rds
from core.security import session_required

from core.reports import (
  generate_html, 
  generate_csv, 
  generate_txt,
  generate_xml
)

from flask import (
  Blueprint,
  flash,
  redirect,
  send_from_directory
)

download = Blueprint('download', __name__,
                      template_folder='templates')

@download.route('/download/<file>')
@session_required
def view_download(file):
  if not file:
    return {'status':'file is missing'}, 400
  
  if file == 'server_log':
    response = send_from_directory(directory='logs', 
                                    filename=config.WEB_LOG,
                                    as_attachment=True,
                                    cache_timeout=0)
    return response
  
  else:
    data = rds.get_vuln_data()
    conf = rds.get_scan_config()
    
    if not data and not conf:
      flash('There is no data in the system for report generation', 'error')
      return redirect('/reports')
    
    if file == 'report_html':  
      report_file = generate_html(data, conf)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    
    elif file == 'report_txt':
      report_file = generate_txt(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
    elif file == 'report_csv':
      report_file = generate_csv(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response

    elif file == 'report_xml':
      report_file = generate_xml(data)
      response = send_from_directory(directory='reports', 
                                      filename=report_file,
                                      as_attachment=True,
                                      cache_timeout=0)
      return response
