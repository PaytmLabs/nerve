import sys
import logging

from config import LOG_LEVEL, WEB_LOG

logger = logging.getLogger('NERVE')
level  = logging.getLevelName(LOG_LEVEL)
logger.setLevel(level)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(level)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(process)d - %(message)s')
ch.setFormatter(formatter)

fh = logging.FileHandler('logs/' + WEB_LOG)
fh.setFormatter(formatter)
fh.setLevel(level)

logger.addHandler(fh)
logger.addHandler(ch)
