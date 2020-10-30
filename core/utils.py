import os
import re
import json
import socket
import requests
import uuid
import datetime
import validators
import psutil
import hashlib
import ipaddress

from core.logging import logger
from config import WEB_LOG, USER_AGENT
from urllib.parse import urlparse
from version import VERSION

class Utils:
  def generate_uuid(self):
    return str(uuid.uuid4()).split('-')[0]
  
  def get_date(self):
    return datetime.datetime.now().strftime('%Y-%m-%d')

  def get_datetime(self):
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

  def clear_log(self):
    open('logs/' + WEB_LOG, 'w').close()

  def is_string_safe(self, string):
    if re.findall('[^A-Za-z0-9,. ]', string):
      return False
    return True
  
  def is_user_root(self):
    if os.geteuid() == 0:
      return True
    return False
  
  def hash_sha1(self, text):
    return hashlib.sha1(f'{text}'.encode()).hexdigest()
  
  def sev_to_human(self, severity):
    color_map = {4:'Critical', 3:'High', 2:'Medium' , 1:'Low', 0:'Informational'}
    return color_map[severity]
  
  def is_string_url(self, url):
    if not url:
      return False
    
    res = urlparse(url)
    if res.scheme and res.netloc:
      return True
    return False

  def is_string_email(self, email):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
      return False
    return True

  def is_version_latest(self):
    try:
      resp = requests.get('https://raw.githubusercontent.com/PaytmLabs/nerve/master/version.py', timeout=10)
      repo_ver = resp.text.split("'")[1].replace('.', '')
      curr_ver = VERSION.replace('.', '').replace('\'', '')
      if int(repo_ver) > int(curr_ver):
        return False
      return True
    except:
      return True
  
class Network:
  def get_nics(self):
    return psutil.net_if_addrs()
  
  def is_network(self, network):
    try:
      return ipaddress.ip_network(network, strict=False)
    except ValueError:
      return False
  
  def is_ip(self, addr):
    try:
      return ipaddress.ip_address(addr)
    except ValueError:
      return False
  
  def is_dns(self, addr):
    if validators.domain(addr):
      return True
    return False
  
  def is_valid_port(self, port):
    try:
      if 0 <= port <= 65535:
        return True
      return False
    except TypeError:
      return False

  def get_primary_ip(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

  def is_network_in_denylist(self, network):
    hosts_limit = 65535
    deny_list = ['127.0.0.1', '127.0.0.1/32', '127.0.']
    
    for deny in deny_list:
      if network.startswith(deny):
        return True
    
    if ipaddress.ip_network(network, strict=False).num_addresses > hosts_limit:
      return True
    
    return False

class Integration:
  def submit_slack(self, hook, data={}):
    try:
      if not data:
        logger.info('Did not send slack notification, scan did not yield any result.')
        return

      fields = []
      
      for _, value in data.items():
        if value['rule_sev'] == 0:
            continue
          
        for k, v in value.items():
          
          if not v:
            v = 'N/A'
          
          fields.append({'title':k, 'value':v, 'short':False})
        
      slack_data = {
          "color": '#000000',
          "pretext":"<!channel> NERVE Notification",
          "author_name": ':warning: Notification',
          "title": 'NERVE Report',
          "fields": fields,
        }
      response = requests.post(hook, data=json.dumps(slack_data))
      
      if response.status_code != 200:
        logger.error('Could not submit slack hook: {}'.format(response.text))
      else:
        logger.info('Submitted slack hook')
    except Exception as e:
      logger.error('Could not submit slack hook: {}'.format(e))
    
    return
  
  def submit_webhook(self, webhook, cfg, data={}):
    logger.info('Sending the webhook...')
    try:
      data = {'status':'done', 'vulnerabilities':data, 'scan_config':cfg}
      requests.post(webhook, 
                    json=data, 
                    headers={'User-Agent':USER_AGENT, 
                            'Content-Type':'application/json'},
                    verify=False)
      return True
    except Exception as e:
      logger.error('Could not submit webhook: {}'.format(e))
    
    return

class Charts:
  def make_doughnut(self, data):
    vuln_count = {0:0, 1:0, 2:0, 3:0, 4:0}
    if data:
      for k, v in data.items():
        vuln_count[v['rule_sev']] += 1

    return vuln_count
  
  def make_radar(self, data):
    ports = {}
    if data:
      for k, v in data.items():
        if v['port'] not in ports:
          ports[v['port']] = 1
        else:
          ports[v['port']] += 1
          
    return ports