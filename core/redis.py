import config
import sys
import redis
import threading
import pickle

from core.logging import logger
from core.utils   import Utils

class RedisManager:
  def __init__(self):
    self.utils = Utils()
    self.r = None
    try:
      self.conn_pool = redis.ConnectionPool(host=config.RDS_HOST, port=config.RDS_PORT, password=config.RDS_PASSW, db=0)
      self.r = redis.Redis(connection_pool=self.conn_pool)
    except TimeoutError:
      logger.error('Redis Connection Timed Out!')
      sys.exit(1)
  
  def store(self, key, value):
    res = self.r.set(key, value)
    if res:
      return True
    return False

  def store_json(self, key, value):
    if key and value:
      pickle_v = pickle.dumps(value)
      result = self.r.set(key, pickle_v)
      if result:
        return True
    return False
  
  def store_topology(self, host):
    self.r.sadd("sess_topology", host)
  
  def get_slack_settings(self):
    return self.r.get('p_settings_slack')
  
  def get_email_settings(self):
    settings = self.r.get('p_settings_email')
    if settings:
      settings = pickle.loads(settings)
    
    return settings
    
  def store_vuln(self, value):
    key = '{}{}{}{}'.format(value['ip'], value['port'], 
                            value['rule_id'], value['rule_details'])
    key_hash = 'vuln_' + self.utils.hash_sha1(key)
    
    if self.r.exists(key_hash):
      return False
    
    logger.info('Vulnerability detected')
    
    self.store_json(key_hash, value)
    
  def store_sca(self, key, value):
    key = 'sca_' + key
    self.store_json(key, value)
  
  def store_inv(self, key, value):
    key = 'inv_' + key
    self.store_json(key, value)
    
  def store_sch(self, value):
    key = 'sch_' + value
    self.store(key, value)
    
  def get_ips_to_scan(self, limit):
    data = {}
    count = 0
    
    for key in self.r.scan_iter(match="sch_*"):
      count += 1
      value = self.r.get(key)
      
      if not value:
        self.r.delete(key)
        return
    
      ip = key.decode('utf-8').split('_')[1]
      data[ip] = {}

      self.r.delete(key)
      
      if count == limit:
        break

    return data

  def get_scan_data(self):
    kv = {}
    ip_key = None
    
    for k in self.r.scan_iter(match="sca_*"):
      ip_key = k.decode('utf-8')
      break # only get one key

    if ip_key:
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          if result:
            ip = ip_key.split('_')[1]
            kv[ip] = result
            self.r.delete(ip_key)
        except pickle.UnpicklingError as e:
          logger.error('Error unpickling %s' % e)
          logger.debug('IP Key: %s' % ip_key)

    return kv

  def get_vuln_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="vuln_*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv
  
  def get_vuln_by_id(self, alert_id):
    vuln = self.r.get(alert_id)
    if vuln:
      return pickle.loads(vuln)
    return None

  def get_inventory_data(self):
    kv = {}
    for ip_key in self.r.scan_iter(match="inv*"):
      data = self.r.get(ip_key)
      if data:
        try:
          result = pickle.loads(data)
          kv[ip_key.decode('utf-8')] = result
        except:
          logger.error('Error retrieving key')

    return kv
  
  def get_topology(self):
    return self.r.smembers("sess_topology")

  def get_scan_config(self):
    cfg = self.r.get('sess_config')
    if cfg: 
      return pickle.loads(cfg)
    return {}
  
  def get_scan_progress(self):
    count = 0
    for k in self.r.scan_iter(match="sch_*"):
      count += 1
    return count
  
  def get_exclusions(self):
    exc = self.r.get('p_rule-exclusions')
    if exc: 
      return pickle.loads(exc)
    return {}
    
  def get_last_scan(self):
    return self.r.get('p_last-scan')
  
  def get_scan_count(self):
    return self.r.get('p_scan-count')
  
  def is_attack_active(self):
    for i in threading.enumerate():
      if i.name.startswith('rule_'):
        return True
    return False

  def is_scan_active(self):
    return self.get_scan_progress()
  
  def is_session_active(self): 
    if self.is_scan_active() or self.is_attack_active():
      return True
    return False
  
  def get_session_state(self):
    state = self.r.get('sess_state')
    if state:
      return state.decode('utf-8')
    return None
  
  def create_session(self):
    self.store('sess_state', 'created')
    self.r.incr('p_scan-count')
    self.r.set('p_last-scan', self.utils.get_datetime())
    
  def start_session(self):
    logger.info('Starting a new session...')
    self.store('sess_state', 'running')
    
  def end_session(self):
    logger.info('The session has ended.')
    self.store('sess_state', 'completed')
  
  def clear_session(self):
    for prefix in ('vuln', 'sca', 'sch', 'inv'):
      for key in self.r.scan_iter(match="{}_*".format(prefix)):
        self.r.delete(key)
      
    for i in ('topology', 'config', 'state'):
      self.r.delete('sess_{}'.format(i))
    
    self.utils.clear_log()
  
  
  def is_ip_blocked(self, ip):
    key = 'logon_attempt-{}'.format(ip)
    attempts = self.r.get(key)
    if attempts:
      if int(attempts) >= config.MAX_LOGIN_ATTEMPTS:
        return True
    else:
      self.r.set(key, 1, ex=300)  
    return False
  
  def log_attempt(self, ip):
    key = 'logon_attempt-{}'.format(ip)
    self.r.incr(key)
    
  def queue_empty(self):
    if self.r.dbsize() == 0:
      return True
    return False

  def db_size(self):
    return self.r.dbsize()
  
  def initialize(self):
    self.clear_session()
    self.r.set('p_scan-count', 0)
    self.r.set('p_last-scan', 'N/A')
    
  def flushdb(self):
    self.r.flushdb()

  def delete(self, key):
    self.r.delete(key)
    
rds = RedisManager()