import os
import sys
from qpylib import qpylib
from qpylib import util_qpylib
from qpylib.encdec import Encryption
import logging
import logging.handlers
import re
import socket


APP_BASE_NAME = 'qvti'
API_VERSION = '12.0'

if getattr(sys, 'frozen', False):
    APP_FOLDER = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_FOLDER = os.path.dirname(os.path.abspath(__file__))

STORE_FOLDER = os.path.abspath(os.path.join(APP_FOLDER, '../store'))

LOG_FOLDER = os.path.join(STORE_FOLDER, 'log')
if not os.path.exists(LOG_FOLDER):
    os.mkdir(LOG_FOLDER)
LOG_FILE = os.path.join(LOG_FOLDER, '%s%s' % (APP_BASE_NAME, '.log'))

CONF_FOLDER = os.path.join(STORE_FOLDER, 'conf')
if not os.path.exists(CONF_FOLDER):
    os.mkdir(CONF_FOLDER)
CONF_FILE = os.path.join(CONF_FOLDER, '%s%s' % (APP_BASE_NAME, '.cfg'))
PID_FILE = os.path.join(CONF_FOLDER, '%s%s' % (APP_BASE_NAME, '.pid'))


LIB_FOLDER = os.path.join(APP_FOLDER, 'lib')
if not os.path.exists(LIB_FOLDER):
    os.mkdir(LIB_FOLDER)
if os.path.isdir(LIB_FOLDER):
    sys.path.append(LIB_FOLDER)
    for zipped in os.listdir(LIB_FOLDER):
        extension = os.path.splitext(zipped)[1]
        if extension in [".egg", ".whl", ".zip"]:
            sys.path.append('%s/%s' % (LIB_FOLDER, zipped))


def get_logger(filename, max_bytes=3*1024*1024, backup_count=10):
    logger = logging.getLogger(APP_BASE_NAME)
    if not len(logger.handlers):
        log_format = '%(asctime)-15s %(levelname)-8s %(filename)s[%(process)d]: %(message)s'
        file_formatter = logging.Formatter(log_format)
        file_handler = logging.handlers.RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=backup_count)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)
    return logger


LOGGER = get_logger(LOG_FILE)

CONSOLE_IP = qpylib.get_console_address()
BASE_URL = 'https://%s/api' % CONSOLE_IP

if util_qpylib.is_sdk():
    LOGGER.info('SDK detected: SSL verification is OFF')
    APP_CERT_LOCATION = False
else:
    APP_CERT_LOCATION = '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'
    if not os.path.exists(APP_CERT_LOCATION):
        LOGGER.warning('No default certificate bundle exists at: %s - will use True as a value' % APP_CERT_LOCATION)
        APP_CERT_LOCATION = True

LOG_RE = re.compile('\\.log(\\.\\d+)?$')

CONSOLE_FQDN = None

if not util_qpylib.is_sdk():
    try:
        CONSOLE_FQDN = qpylib.get_console_fqdn()
        LOGGER.info('Console FQDN (from qpylib): %s' % CONSOLE_FQDN)
        BASE_URL = 'https://%s/api' % CONSOLE_FQDN
        LOGGER.info('BASE_URL: %s' % BASE_URL)
    except:
        LOGGER.exception('Failed to get console FQDN:')
        BASE_URL = 'https://%s/api' % CONSOLE_IP
        LOGGER.info('BASE_URL: %s' % BASE_URL)
else:
    BASE_URL = 'https://%s/api' % CONSOLE_IP
    LOGGER.info('SDK detected: will use IP instead of FQDN')
    LOGGER.info('BASE_URL: %s' % BASE_URL)

if util_qpylib.is_sdk():
    app_uuid = os.environ.get('QRADAR_APP_UUID', False)
    if not app_uuid:
        os.environ['QRADAR_APP_UUID'] = 'a035c4d7-39a2-4e3b-9ef4-0811beaed6f6'
