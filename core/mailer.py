import smtplib
import ssl

from email.mime.multipart  import MIMEMultipart
from email.mime.text       import MIMEText
from email.header          import Header
from email.utils           import formataddr

from core.redis import rds
from core.utils import Utils

def send_email(settings, data=None):
  utils = Utils()
  
  keys = ('host', 'port', 'user', 'pass', 'to_addr', 'from_addr', 'ssl_type', 'action')
  if not all(elem in settings for elem in keys):
    return ('Error, missing settings', 400)
    
  if not settings['host'] or not settings['port']:
    return ('SMTP address or SMTP port are empty', 400)
  
  if not isinstance(settings['port'], int):
    return ('SMTP Port must be a number', 400)
  
  if not settings['from_addr'] or not settings['to_addr']:
    return ('FROM or TO Address are empty', 400)

  if not utils.is_string_email(settings['from_addr']) or \
     not utils.is_string_email(settings['to_addr']):
       return ('FROM or TO addresses are not valid emails', 400)
     
  if settings['ssl_type'] not in ('starttls', 'ssl'):
    return ('Error in security settings (must be starttls or ssl).', 400)
  
  if settings['action'] not in ('save', 'test', 'send'):
    return ('Error, action is not supported', 400)
  
  msg = MIMEMultipart('alternative')
  subject = ''
  
  if settings['action'] == 'test':
    subject = 'Test by NERVE'
    part = MIMEText('This is a test.', 'plain')
    msg.attach(part)
    
  elif settings['action'] == 'send':
    subject = 'Assessment Complete'
    part = MIMEText(str(data), 'plain')
    part.add_header('Content-Disposition', 
                    'attachment', 
                    filename='assessment.json')
    msg.attach(part)
  
  elif settings['action'] == 'save':
    rds.store_json('p_settings_email', settings)
    return ('OK, Saved.', 200)
  
  context = ssl.create_default_context()
  
  msg['From'] = formataddr((str(Header('NERVE Security', 'utf-8')), settings['from_addr']))
  msg['To'] = settings['to_addr']
  msg['Subject'] = subject
  
  try:
    if settings['ssl_type'] == 'ssl':
      # ssl
      server = smtplib.SMTP_SSL(settings['host'], settings['port'], context=context)
    else:
      # starttls
      server = smtplib.SMTP(settings['host'], settings['port'])
      server.starttls(context=context)
    
    server.login(settings['user'], settings['pass'])
    server.sendmail(settings['from_addr'], settings['to_addr'], msg.as_string())
    server.quit()
    return ('Message was sent successfully', 200)
  
  except Exception as e:
    return ('Message was could not be sent {}'.format(e), 500)

  