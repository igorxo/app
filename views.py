# Licensed Materials - Property of IBM
# 5725I71-CC011829
# (C) Copyright IBM Corp. 2015, 2020. All Rights Reserved.
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp.

from flask import Blueprint, render_template, current_app, send_from_directory, request, jsonify, send_file
from qpylib import qpylib

from datetime import datetime
from zipfile import ZipFile
import traceback
import mimetypes
from requests.exceptions import SSLError

from . app_init import *
from . model import Requester, Config

# pylint: disable=invalid-name
viewsbp = Blueprint('viewsbp', __name__, url_prefix='/')

mimetypes.add_type('image/svg+xml', '.svg')

LOGGER.info(u'starting views...')
LOGGER.info(u'console address: %s' % CONSOLE_IP)

# re-save config on init to remove plain auth token when upgrading
# from older versions
config = Config(CONF_FILE)
config.save_config()


@viewsbp.route('/index')
def index():
    config = Config(CONF_FILE)
    vt_keys = '\n'.join(config.vt_keys)
    vt_enginesc1 = '\n'.join(config.vt_enginesc1)
    vt_enginesc2 = '\n'.join(config.vt_enginesc2)
    max_hashes = config.max_hashes
    rate_limit = config.rate_limit
    return render_template('index.html', vt_keys=vt_keys, vt_enginesc1=vt_enginesc1, vt_enginesc2=vt_enginesc2, max_hashes=max_hashes, rate_limit=rate_limit)


# The presence of this endpoint avoids a Flask error being logged when a browser
# makes a favicon.ico request. It demonstrates use of send_from_directory
# and current_app.
@viewsbp.route('/favicon.ico')
def favicon():
    return send_from_directory(current_app.static_folder, 'favicon-16x16.png')


def check_connectivity(auth_token=None):
    if auth_token is None:
        return False
    else:
        try:
            requester = Requester(base_url=BASE_URL, version=API_VERSION, api_key=auth_token)
            return requester.check_connectivity()
        except:
            return False


@viewsbp.route('/save_auth', methods=['POST'])
def save_auth():
    auth_token = request.form.get('authTokenField', None)
    if check_connectivity(auth_token):
        config = Config(CONF_FILE)
        config.save_auth_key_encrypted(auth_token)
        return jsonify(True)
    else:
        return jsonify(False)


@viewsbp.route('/save_vt_keys', methods=['POST'])
def save_vt_keys():
    try:
        vt_keys_string = request.form.get('vtKeysField', '')
        vt_keys = [k.strip() for k in vt_keys_string.split('\n') if k]
        config = Config(CONF_FILE)
        config.vt_keys = vt_keys
        config.save_config()
        return jsonify(True)
    except:
        return jsonify(False)

@viewsbp.route('/save_vt_engines', methods=['POST'])
def save_vt_engines():
    try:
        vt_enginesc1_string = request.form.get('vtEnginesClass1Field', '')
        vt_enginesc2_string = request.form.get('vtEnginesClass2Field', '')
        vt_enginesc1 = [k.strip() for k in vt_enginesc1_string.split('\n') if k]
        vt_enginesc2 = [k.strip() for k in vt_enginesc2_string.split('\n') if k]
        config = Config(CONF_FILE)
        config.vt_enginesc1 = vt_enginesc1
        config.vt_enginesc2 = vt_enginesc2
        config.save_config()
        return jsonify(True)
    except:
        return jsonify(False)


@viewsbp.route('/save_advanced', methods=['POST'])
def save_advanced():
    try:
        max_hashes = int(request.form.get('maxHashField', None))
        rate_limit = int(request.form.get('maxRateField', None))
        config = Config(CONF_FILE)
        config.max_hashes = max_hashes
        config.rate_limit = rate_limit
        config.save_config()
        return jsonify(True)
    except:
        return jsonify(False)


@viewsbp.route('/get_logs')
def get_logs():
    # remove old zipped logs
    for f in os.listdir(LOG_FOLDER):
        if f.endswith('.zip'):
            filename = os.path.join(LOG_FOLDER, f)
            if os.path.isfile(filename):
                os.unlink(filename)

    try:
        zip_basename = '%s_%s.zip' % (APP_BASE_NAME, datetime.now().strftime('%Y%m%d%H%M%S'))
        zip_filename = os.path.join(LOG_FOLDER, zip_basename)
        with ZipFile(zip_filename, 'w') as zf:
            for f in os.listdir(LOG_FOLDER):
                if LOG_RE.search(f):
                    zf.write(os.path.join(LOG_FOLDER, f))
        return send_file(zip_filename, as_attachment=True, cache_timeout=-1)
    except:
        LOGGER.error('error compressing log files: %s' % traceback.format_exc())


@viewsbp.context_processor
def inject_now():
    return {'now': datetime.now()}


@viewsbp.context_processor
def inject_auth_token():
    config = Config(CONF_FILE)
    defined = config.auth_token is not None
    valid = False
    if defined:
        valid = check_connectivity(config.auth_token)
    return {'auth_token': {'defined': defined, 'valid': valid}}


@viewsbp.context_processor
def inject_ssl_valid():
    config = Config(CONF_FILE)
    ssl_valid = True
    try:
        requester = Requester(base_url=BASE_URL, version=API_VERSION, api_key=config.auth_token)
        requester.check_connectivity()
    except SSLError:
        ssl_valid = False
        LOGGER.error("SSL Verification Failed")
    return {'ssl_valid': ssl_valid}