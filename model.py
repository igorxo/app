from . app_init import *
import os
import json
import requests


UNLICENSED_MAX_HASHES = 1
UNLICENSED_RATE_LIMIT = 4


INITIAL_CONFIG = {
    'max_hashes': UNLICENSED_MAX_HASHES,
    'rate_limit': UNLICENSED_RATE_LIMIT,
    'vt_keys': [],
    'vt_enginesc1': [],
    'vt_enginesc2': []
}


class Config:
    def __init__(self, config_file):
        self.config_file = config_file
        self.auth_token = self.get_auth_key_decrypted()
        self.max_hashes = INITIAL_CONFIG['max_hashes']
        self.rate_limit = INITIAL_CONFIG['rate_limit']
        self.vt_keys = INITIAL_CONFIG['vt_keys']
        self.vt_enginesc1 = INITIAL_CONFIG['vt_enginesc1']
        self.vt_enginesc2 = INITIAL_CONFIG['vt_enginesc2']
        self.load_config()

    def log_config(self):
        config = {
            'auth_token': 'xxx-xxx-xxx-xxx',
            'max_hashes': self.max_hashes,
            'rate_limit': self.rate_limit,
            'vt_keys': '%d keys defined' % len(self.vt_keys),
            'vt_enginesc1': '%d engines class 1 defined' % len(self.vt_enginesc1),
            'vt_enginesc2': '%d engines class 2 defined' % len(self.vt_enginesc2)
        }
        LOGGER.debug('Config: %s' % str(config))

    def load_config(self):
        if not os.path.exists(self.config_file):
            LOGGER.warning('No config file found. Default config file will be created.')
            with open(self.config_file, 'w') as fp:
                json.dump(INITIAL_CONFIG, fp)
                LOGGER.info('Config file created: %s' % self.config_file)
        else:
            with open(self.config_file) as fp:
                config = json.load(fp)
            self.max_hashes = config['max_hashes']
            self.rate_limit = config['rate_limit']
            self.vt_keys = config['vt_keys']
            self.vt_enginesc1 = config['vt_enginesc1']
            self.vt_enginesc2 = config['vt_enginesc2']
            LOGGER.debug('Config loaded')
            self.log_config()

    def get_auth_key_decrypted(self):
        result = None
        try:
            secret_handler = Encryption({
                'name': 'auth_key',
                'user': 'appuser'
            })
            result = secret_handler.decrypt()
        except:
            LOGGER.exception('Failed to decrypt auth_key')
            return None
        if not result:
            return None
        return result

    def save_auth_key_encrypted(self, key):
        try:
            secret_handler = Encryption({
                'name': 'auth_key',
                'user': 'appuser'
            })
            result = secret_handler.encrypt(key)
            if not result:
                LOGGER.error('Failed to encrypt auth key')
                return False
            LOGGER.info('Auth key saved.')
            self.auth_token = key
            return True
        except:
            LOGGER.exception('Failed to encrypt auth key')
            return False

    def save_config(self):
        LOGGER.info('Saving config...')
        config = {
            'max_hashes': self.max_hashes,
            'rate_limit': self.rate_limit,
            'vt_keys': self.vt_keys,
            'vt_enginesc1': self.vt_enginesc1,
            'vt_enginesc2': self.vt_enginesc2
        }
        with open(self.config_file, 'w') as fp:
            json.dump(config, fp)
        LOGGER.info('Config saved.')
        self.log_config()


class Requester:
    SUCCESS_CODES = (200, 201, 202)

    def __init__(self, base_url, version, api_key):
        self.base_url = base_url
        self.version = version
        self.api_key = api_key
        self.headers = {
            'SEC': self.api_key,
            'Version': self.version,
            'Accept': 'application/json'
        }
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def check_connectivity(self, endpoint=None):
        if endpoint is None:
            endpoint = '/ariel/databases'
        raw_response = requests.get('%s%s' % (self.base_url, endpoint), headers=self.headers, verify=APP_CERT_LOCATION)
        response_code = raw_response.status_code
        if response_code == 200:
            return True
        return False

    def api_call(self, endpoint, method_name='get', fields_str=None,
                 filter_str=None, sort_str=None, range_str=None, parameters=None, data=None):
        params = dict()
        if parameters is not None:
            if isinstance(parameters, dict):
                for key in parameters:
                    params[key] = parameters[key]
        if fields_str is not None:
            params['fields'] = fields_str
        if filter_str is not None:
            params['filter'] = filter_str
        if sort_str is not None:
            params['sort'] = sort_str

        call_headers = self.headers.copy()
        if range_str is not None:
            call_headers['Range'] = range_str

        method = getattr(requests, method_name.lower(), None)
        if method is None:
            return False, 405, '%s method is not supported' % method_name

        raw_response = method('%s%s' % (self.base_url, endpoint), headers=call_headers, data=data,
                              params=params, verify=APP_CERT_LOCATION)
        response_code = raw_response.status_code
        LOGGER.debug('Endpoint: %s; Return code: %s' % (endpoint, response_code))
        json_data = raw_response.json()
        if response_code in Requester.SUCCESS_CODES:
            return True, response_code, json_data
        else:
            return False, response_code, json_data['message']
