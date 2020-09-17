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
    self.headers = {
      'User-Agent':USER_AGENT
      }
    
  def http_request(self, ip, port, headers=None, follow_redirects=True, uri='/'):
    resp = None

    if headers:
      self.headers = {**headers, **self.headers}

    url = 'http://{}:{}{}'.format(ip, port, uri)
    
    if port == 443 or port == 8443 or '443' in str(port):
      url = 'https://{}:{}{}'.format(ip, port, uri)
    try:
      resp = requests.get(url, verify=False, timeout=8, allow_redirects=follow_redirects, headers=self.headers)
      
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

  def socket_banner(self, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    socket_banner = None
    
    sock.settimeout(6)
    try:
      result = sock.connect_ex((ip, port))
      if result == 0:
        socket_banner = str(sock.recv(1024))
    except Exception as e:
      logger.debug('socket_open banner {} {} {}'.format(ip, port, e))
    
    finally:
      sock.close()

    return socket_banner
  
  def socket_open(self, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    try:
      result = sock.connect_ex((ip, port))
      if result == 0:
        return True
    except Exception as e:
      pass

    finally:
      sock.close()

    return False

  def is_ssh(self, ip, port):
    is_ssh = False
    banner = self.socket_banner(ip, port)
    if banner and 'SSH' in str(banner):
      is_ssh = True

    return is_ssh

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
      
    try:
      req = requests.get('https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version={}'.format(cpe), verify=False, timeout=5)
      if req:
        soup = BeautifulSoup(req.text, 'html.parser')
        for a in soup.find_all('a', href=True):
          if a.has_attr('data-testid') and a.contents:
            sevs = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            if any(word in a.contents[0] for word in sevs):
              score, sev = a.contents[0].split()
              if float(score) >= 8.9:
                return True
    except:
      pass

    return False
