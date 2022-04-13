import sys
import socket
import shlex
import requests
import urllib3

from subprocess import Popen, PIPE
from socket import gethostname
from config import USER_AGENT
from http.client import RemoteDisconnected    
from urllib3.exceptions import ProtocolError
from bs4 import BeautifulSoup
from core.logging import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Triage:
  def __init__(self):
    self.global_timeout = 10
    self.headers = {
      'User-Agent':USER_AGENT
      }
    
    # this dictionary maps HTTP verbs to the correct requests method
    self.http_verb__requests_method__map = {
        'GET': requests.get,
        'POST': requests.post,
        'HEAD': requests.head,
        'OPTIONS': requests.options,
        'PUT': requests.put,
        'DELETE': requests.delete
    }

    self.severity_labels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
  def http_request(self, ip, port, method="GET", params=None, data=None, json=None, headers=None, follow_redirects=True, timeout=None, uri='/'):
    method = method.upper()

    if method not in self.http_verb__requests_method__map.keys():
      logger.error("HTTP Method '{}' is not supported.".format(method))
      return
    
    resp = None
    
    scheme = 'https' if bool('443' in str(port)) else 'http'
    url = '{}://{}:{}{}'.format(scheme, ip, port, uri)
    
    if headers:
      self.headers = {**headers, **self.headers}
    
    if not timeout:
      timeout = self.global_timeout

    try:
      # we use the "HTTP verbs => requests method" map to get the correct requests method
      # that can be called here, according to the value of method
      func = self.http_verb__requests_method__map[method]
      
      # this set of parameters is used by all requests methods that we can call here
      func_params = {
        'verify': False,
        'timeout': timeout,
        'params': params,
        'allow_redirects': follow_redirects,
        'headers': self.headers
      }
      
      # this set of parameters is additional in case
      # we use POST, PUT or DELETE
      if method in ['POST', 'PUT', 'DELETE']:
        func_params.update({
          'data': data,
          'json': json
        })

      # we can call the right requests method with the right parameters
      resp = func(url, **func_params)

    except requests.exceptions.ConnectTimeout:
      logger.debug('http_request {} {} (Timeout)'.format(ip, port))
    except urllib3.exceptions.MaxRetryError:
      logger.debug('http_request {} {} (MaxRetryError)'.format(ip, port))
    except requests.exceptions.SSLError:
      logger.debug('http_request {} {} (SSL Error)'.format(ip, port))
    except requests.exceptions.ConnectionError as e: 
      logger.debug('http_request {} {} (Connection Error: {})'.format(ip, port, e))
    except requests.exceptions.Timeout:
      logger.debug('http_request {} {} {} (Timeout)'.format(ip, port, url))
    except requests.exceptions.ReadTimeout:
      logger.debug('http_request {} {} (Read Timeout)'.format(ip, port))
    except ProtocolError:
      logger.debug('http_request {} {} (Protocol Error)'.format(ip, port))
    except RemoteDisconnected:
      logger.debug('http_request {} {} (Remote Disconnected)'.format(ip, port))
    except Exception as e:
      logger.debug('http_request {} {} (Unknown Error: {})'.format(ip, port, e))
    
    return resp

  def string_in_headers(self, resp, string):
    for k, v in resp.headers.items():
      s = string.upper()
      if s in k.upper() or s in v.upper():
        return resp
    return False

  def get_tcp_socket_banner(self, ip, port, timeout=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    socket_banner = None
    
    if not timeout:
      timeout = self.global_timeout
      
    sock.settimeout(timeout)
    
    try:
      result = sock.connect_ex((ip, port))
      if result == 0:
        socket_banner = str(sock.recv(1024))
    except:
      pass
    
    finally:
      sock.close()

    return socket_banner
  
  def is_socket_open(self, ip, port, timeout=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_open = False
    
    if not timeout:
      timeout = self.global_timeout
    
    sock.settimeout(timeout)
    
    try:
      is_open = bool(sock.connect_ex((ip, port)) == 0)
    except:
      pass

    finally:
      sock.close()

    return is_open

  def run_cmd(self, command):
    result = None
    p = Popen(shlex.split(command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
    (stdout, stderr) = p.communicate()
    
    if p.returncode == 0:
      result = stdout
    else:
      result = stderr
    return result

  def has_cves(self, cpe):
    if not any(char.isdigit() for char in cpe):
      return False
      
    req = self.http_request('nvd.nist.gov', 443, method="GET", uri='/vuln/search/results?form_type=Advanced&cves=on&cpe_version=' + cpe)
    if not req:
      return 
    
    soup = BeautifulSoup(req.text, 'html.parser')
    for a in soup.find_all('a', href=True):
      if a.has_attr('data-testid') and a.contents:
        if any(label in a.contents[0] for label in self.severity_labels):
          score, sev = a.contents[0].split()
          if float(score) >= 8.9:
            return True
    
    return False
