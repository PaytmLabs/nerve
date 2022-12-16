import json
import time
import ipaddress
import requests
import datetime

from core.redis   import rds
from core.utils   import Network, Integration
from core.logging import logger
from core.parser  import ConfParser
from core.mailer  import send_email

def schedule_ips(networks, excluded_networks):
  for network in networks: 
    net = ipaddress.ip_network(network, strict=False)
    for ip_address in net:
      ip_addr = str(ip_address)
      if not isinstance(ip_addr, str):
        continue
      
      if excluded_networks:
        skip = False
        for excluded_network in excluded_networks:
          if ipaddress.ip_address(ip_addr) in ipaddress.ip_network(excluded_network):
            skip = True
        if not skip:
          rds.store_sch(ip_addr)
      
      else:
        rds.store_sch(ip_addr)

def schedule_domains(domains):
  for domain in domains:
    rds.store_sch(domain)
    
def scheduler():
  logger.info('Scheduler process started')
  net_utils = Network()
  int_utils = Integration()
  
  while True:
    time.sleep(10)
    
    config = rds.get_next_scan_config()
    
    if not config:
      #logger.debug('No Config yet')
      continue
    
    conf = ConfParser(config)
   
    if conf.get_cfg_schedule() > datetime.datetime.now():
      #logger.debug('Schedule: ' + conf.get_cfg_schedule().strftime("%m/%d/%Y, %H:%M:%S"))
      #logger.debug('Now: ' + datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S"))
      continue
    
    rds.clear_session()
    logger.info('Starting scan at: ' + conf.get_cfg_schedule().strftime("%m/%d/%Y, %H:%M:%S"))

    networks = conf.get_cfg_networks()
    domains  = conf.get_cfg_domains()
    excluded_networks = conf.get_cfg_exc_networks()
    # Exclude private ip of host from scan
    #excluded_networks.append(net_utils.get_primary_ip() + '/32')
    frequency = conf.get_cfg_frequency()
    
    if frequency == 'once' or frequency == 'schedule':
      rds.start_session()

      if networks:
        schedule_ips(networks, excluded_networks)
      
      if domains:
        schedule_domains(domains)
      
      checks = 0

      while True:
        if rds.is_session_active():
          checks = 0
        else:
          checks += 1 
        
        if checks == 10:
          logger.info('Session is about to end...')
          webhook = conf.get_cfg_webhook()
          email_settings = rds.get_email_settings()
          slack_settings = rds.get_slack_settings()
          vuln_data = rds.get_vuln_data()
          
          logger.info('Post assessment actions will now be taken...')
          if webhook:
            int_utils.submit_webhook(webhook, 
                                     cfg  = conf.get_raw_cfg(), 
                                     data = vuln_data)
          
          if email_settings:
            logger.info('Sending email...')
            email_settings['action'] = 'send'
            send_email(email_settings, vuln_data)
          
          if slack_settings:
            int_utils.submit_slack(hook = slack_settings, 
                                   data = vuln_data)

          rds.advance_scan_config_queue()
          rds.end_session()  
          break  
        
        time.sleep(20)
    
    elif frequency == 'continuous':
      rds.start_session()

      if networks:
        schedule_ips(networks, excluded_networks)
      
      if domains:
        schedule_domains(domains)
        
      checks = 0
      
      while True:
        if rds.is_session_active():
          checks = 0
        else:
          checks += 1 
        
        if checks == 10:
          logger.info('Session is about to end...')
          webhook = conf.get_cfg_webhook()
          vuln_data = rds.get_vuln_data()
          
          logger.info('Post assessment actions will now be taken...')
          if webhook:
            int_utils.submit_webhook(webhook, 
                                     cfg = conf.get_raw_cfg(), 
                                     data = vuln_data)
            
          rds.create_session()
          break
          
        time.sleep(20)
