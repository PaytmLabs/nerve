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
    
  def http_request(self, ip, port, method="GET", params=None, data=None, json=None, headers=None, follow_redirects=True, timeout=None, uri='/'):
    resp = None

    if headers:
      self.headers = {**headers, **self.headers}

    if method not in ('GET', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'HEAD'):
      logger.error('HTTP Method is not supported.')
      return
    
    if not timeout:
      timeout = self.global_timeout

    url = 'http://{}:{}{}'.format(ip, port, uri)
    
    if port == 443 or port == 8443 or '443' in str(port):
      url = 'https://{}:{}{}'.format(ip, port, uri)
    try:
      if method == 'GET':
        resp = requests.get(url, verify=False, timeout=timeout, params=params, allow_redirects=follow_redirects, headers=self.headers)
      elif method == 'PUT':
        resp = requests.put(url, verify=False, timeout=timeout, params=params, data=data, json=json, allow_redirects=follow_redirects, headers=self.headers)
      elif method == 'POST':
        resp = requests.post(url, verify=False, timeout=timeout, params=params, data=data, json=json, allow_redirects=follow_redirects, headers=self.headers)
      elif method == 'OPTIONS':
        resp = requests.options(url, verify=False, timeout=timeout, params=params, allow_redirects=follow_redirects, headers=self.headers)
      elif method == 'DELETE':
        resp = requests.delete(url, verify=False, timeout=timeout, params=params, data=data, json=json, allow_redirects=follow_redirects, headers=self.headers)
      elif method == 'HEAD':
        resp = requests.head(url, verify=False, timeout=timeout, params=params, allow_redirects=follow_redirects, headers=self.headers)
      else:
        # Default to GET.
        resp = requests.get(url, verify=False, timeout=timeout, params=params, data=data, json=json, allow_redirects=follow_redirects, headers=self.headers)

      
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
      if string in k or string in v:
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
    
    if not timeout:
      timeout = self.global_timeout
    
    sock.settimeout(timeout)
    
    try:
      result = sock.connect_ex((ip, port))
      if result == 0:
        return True
    except:
      pass

    finally:
      sock.close()

    return False

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
        sevs = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if any(word in a.contents[0] for word in sevs):
          score, sev = a.contents[0].split()
          if float(score) >= 8.9:
            return True
    
    return False
