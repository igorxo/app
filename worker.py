from . app_init import *
from . model import Requester

import requests
import os
import json
import time
import socket
import itertools
import aiohttp
import asyncio

from datetime import datetime

class WorkerConfig:
    def __init__(self, config_file):
        self.config_file = config_file
        self.is_config = False

        if not os.path.exists(self.config_file):
            LOGGER.warning('No config file found: %s' % self.config_file)
            self.is_config = False
        else:
            with open(self.config_file) as fp:
                config = json.load(fp)
            self.auth_token = self.get_auth_key_decrypted()
            self.max_hashes = config['max_hashes']
            self.rate_limit = config['rate_limit']
            self.vt_keys = config['vt_keys']
            self.vt_enginesc1 = config['vt_enginesc1']
            self.vt_enginesc2 = config['vt_enginesc2']
            self.is_config = True
            LOGGER.debug('Config loaded: %s' % self.get_log_config_str())

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

    def get_log_config_str(self):
        log_config = {
            'auth_token': 'xxx - xxx - xxx - xxx',
            'max_hashes': self.max_hashes,
            'rate_limit': self.rate_limit,
            'vt_keys': '%s vt keys defined' % len(self.vt_keys),
            'vt_enginesc1': '%s vt engines c1 defined' % len(self.vt_enginesc1),
            'vt_enginesc2': '%s vt engines c2 defined' % len(self.vt_enginesc2)
        }
        return str(log_config)

    def mark_key_failed(self, key):
        try:
            index = self.vt_keys.index(key)
            LOGGER.warning('Key %s marked as failed' % self.vt_keys[index])
            self.vt_keys[index] = '%s%s' % ('FAILED - ', self.vt_keys[index])
            self.save_config()
        except ValueError:
            LOGGER.warning('Can not mark as failed. Key %s not found' % key)

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
        LOGGER.debug('Config: %s' % self.get_log_config_str())


class Sender:
    def __init__(self, dest=None, port=514, protocol='TCP',
                 input_encoding='utf-8', syslog_output_encoding='utf-8',
                 origin_hostname=None):
        self.dest = dest
        self.port = port
        self.input_encoding = input_encoding
        self.syslog_output_encoding = syslog_output_encoding

        if (origin_hostname is not None) and origin_hostname:
            self.origin_hostname = origin_hostname
        else:
            self.origin_hostname = socket.gethostname()

        self.protocol = protocol
        if protocol.upper() == 'TCP':
            self.sock_type = socket.SOCK_STREAM
        elif protocol.upper() == 'UDP':
            self.sock_type = socket.SOCK_DGRAM
        else:
            raise ValueError('Unsupported protocol: %s' % protocol)

        self.socket = None

        try:
            self.connect()
        except Exception as e:
            msg = '[sender] => failed to connect to %s:%s/%s' % (self.dest, self.port, self.protocol)
            LOGGER.error(msg)
            raise e
        LOGGER.info('Created connection to %s:%s/%s' % (self.dest, self.port, self.protocol))

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, self.sock_type)
        self.socket.connect((self.dest, self.port))

    def send(self, msg):
        msg = msg.rstrip()

        if not isinstance(msg, str):
            msg = msg.decode(self.input_encoding)

        date_time = datetime.today().strftime('%b %d %H:%M:%S')
        msg = '<134>%s %s %s\n' % (date_time, self.origin_hostname, msg)

        try:
            self.socket.send(msg.encode(self.syslog_output_encoding))
        except Exception:
            err_msg = '[sender] => error sending message. Retrying...'
            try:
                self.connect()
                self.socket.send(msg.encode(self.syslog_output_encoding))
                err_msg = '%s Success' % err_msg
                LOGGER.warning(err_msg)
            except Exception as e2:
                err_msg = '%s Failed. Exiting' % err_msg
                LOGGER.error(err_msg)
                raise e2


class WorkerInitException(Exception):
    pass


class WorkerQRadarAPIException(Exception):
    pass


class Worker:
    CHECK_TABLE_NAME = 'virustotal_to_check_v2C'
    CLEAN_SET_NAME = 'virustotal_clean'
#    MSG_TEMPLATE = 'type="%s" ip="%s" hash="%s" msg="%s" positives="%s" total="%s" info=[%s]'
    MSG_TEMPLATE = 'type="%s" ip="%s" domain="%s" hash="%s" msg="%s" positives="%s" total="%s" info=[%s]'
    BAD_RATIO = 0.8  # Really malicious
    HIGH_RATIO = 0.5  # Malicious with high probability
    VT_BASE_API = 'https://www.virustotal.com/api/v3/files/'

    def __init__(self):
        self.config = WorkerConfig(CONF_FILE)
        if not self.config.is_config:
            raise WorkerInitException('Can not initialize config')
        self.api_keys = [
            {'key': key, 'timestamp': 0} for key in self.config.vt_keys if not key.lower().startswith('fail')
        ]
        if not len(self.api_keys):
            raise WorkerInitException('Can not initialize config. No valid keys')
        self.current_key_index = 0
        self.sender = Sender(dest=CONSOLE_IP, origin_hostname='vt_hash_checker')
        self.radar_requester = Requester(base_url=BASE_URL, version=API_VERSION, api_key=self.config.auth_token)
#        self.vt_requester = VTRequester()
        LOGGER.debug('Worker inited')
        
        self.hashes = dict()
        self.payback_hash_list = list()
        self.clean_hash_list = list()

        self.vt_keys = []
        for akey in self.api_keys:
            self.vt_keys.append(akey['key'])
        self.iterkeys = itertools.cycle(self.vt_keys)

        self.vtresponses = {}
        
    def refresh_config(self):
        LOGGER.info('Refreshing config....')
        self.config = WorkerConfig(CONF_FILE)
        if not self.config.is_config:
            raise WorkerInitException('Can not initialize config')
        keys_ts_dict = dict()
        for x in self.api_keys:
            keys_ts_dict[x['key']] = x['timestamp']
        self.api_keys = [
            {'key': key, 'timestamp': 0} for key in self.config.vt_keys if not key.lower().startswith('fail')
        ]
        for key in self.api_keys:
            if key['key'] in keys_ts_dict:
                key['timestamp'] = keys_ts_dict[key['key']]
        if not len(self.api_keys):
            raise WorkerInitException('Can not initialize config. No valid keys')
        self.current_key_index = 0

    def remove_key(self):
        LOGGER.warning('Removing failed key: %s' % self.api_keys[self.current_key_index]['key'])
        self.api_keys.pop(self.current_key_index)
        if not self.api_keys:
            LOGGER.error('No more valid keys left')
            return False
        if self.current_key_index >= len(self.api_keys):
            self.current_key_index = 0
        # self.api_keys[self.current_key_index]['timestamp'] = int(time.time())
        return True

    def switch_key(self):
        now_secs = int(time.time())
        self.current_key_index = (self.current_key_index + 1) % len(self.api_keys)
        diff = now_secs - self.api_keys[self.current_key_index]['timestamp']
        if diff < 60:
            LOGGER.info('Sleeping to not overcome the key rate limit')
            time.sleep(61 - diff)
        LOGGER.info('Next key to use: %s' % self.api_keys[self.current_key_index])

    def load_hashes(self):
        endpoint = '/reference_data/tables/%s' % Worker.CHECK_TABLE_NAME
        status, code, data = self.radar_requester.api_call(endpoint=endpoint, method_name='get')
        if status:
            return data
        else:
            LOGGER.error('Failed to fetch hashes to check from QRadar: Code: %s; Data: %s' % (str(code), str(data)))
            raise WorkerQRadarAPIException('Failed to fetch hashed to check from QRadar')

    def purge_hashes(self):
        endpoint = '/reference_data/tables/%s' % Worker.CHECK_TABLE_NAME
        parameters = {
            'purge_only': 'true'
        }
        status, code, data = self.radar_requester.api_call(endpoint=endpoint, method_name='delete',
                                                           parameters=parameters)
        if status:
            return True
        else:
            LOGGER.error('Failed to purge hashes from QRadar: Code: %s; Data: %s' % (str(code), str(data)))
            raise WorkerQRadarAPIException('Failed to purge hashes from QRadar')
    
    '''     def update_hashes(self, refset_name, refset_type, data):
        endpoint = '/reference_data/%s/bulk_load/%s' % (refset_type, refset_name)
        data = json.dumps(data)
        status, code, datum = self.radar_requester.api_call(endpoint=endpoint, method_name='post',
                                                            data=data)
        if status:
            return True
        else:
            LOGGER.error('Failed to update ref data %s: Code: %s; Data: %s' % (refset_name, str(code), str(datum)))
            raise WorkerQRadarAPIException('Failed to update ref data') '''
    
    def update_hashes(self, refset_name, refset_type, data):
        endpoint = '/reference_data/%s/bulk_load/%s' % (refset_type, refset_name)
        data = json.dumps(data)
        status, code, datum = self.radar_requester.api_call(endpoint=endpoint, method_name='post',
                                                            data=data)
        if status:
            return True
        else:
            LOGGER.error('Failed to update ref data %s: Code: %s; Data: %s' % (refset_name, str(code), str(datum)))
            raise WorkerQRadarAPIException('Failed to update ref data')

    def payback_error_data(self, hashes, payback_hash_list):
        LOGGER.debug('Payback list: %s' % str(payback_hash_list))
        payback = dict()
        for hsh in payback_hash_list:
            payback[hsh] = dict()
            for ip in hashes[hsh]:
                payback[hsh][ip] = hashes[hsh][ip]['value']
        self.update_hashes(self.CHECK_TABLE_NAME, 'tables', payback)
        msg = 'type="%s" msg="%s"' % ('error', 'There were errors during the data retrieval from VirusTotal. '
                                               'Some of the hashes were returned back to QRadar')
        self.sender.send(msg)

    def send_messages(self, hashes, clean, low, high, bad, unknown):
        LOGGER.debug('clean: %s, %s' % (str(len(clean)), clean))
        LOGGER.debug('low: %s, %s' % (str(len(low)), low))
        LOGGER.debug('high: %s, %s' % (str(len(high)), high))
        LOGGER.debug('bad: %s, %s' % (str(len(bad)), bad))
        LOGGER.debug('unknown: %s, %s' % (str(len(unknown)), unknown))
        MSG_TEMPLATE = 'type="%s" ip="%s" domain="%s" hash="%s" msg="%s" score="%s" engines="%s" info=[%s]'

        for resphash, haship, hashfile, hashdomain, product, description in clean:
            msg = Worker.MSG_TEMPLATE % ('clean', haship, hashdomain, resphash, 'executable is OK', "0", "", hashfile + " | " + product + " | " + description)
            self.sender.send(msg)
        for resphash, haship, hashfile, hashdomain, detection_points, engines, product, description in low:
            enginesstr = ' | '.join(engines)
            msg = Worker.MSG_TEMPLATE % ('low', haship, hashdomain, resphash,
                                        'executable is potentially malicious, add this hash manually to the clean '
                                        'refset if you are sure it\'s OK', detection_points, enginesstr, hashfile + " | " + product + " | " + description)
            self.sender.send(msg)
        for resphash, haship, hashfile, hashdomain, detection_points, engines, product, description in high:
            enginesstr = ' | '.join(engines)
            msg = Worker.MSG_TEMPLATE % ('high', haship, hashdomain, resphash, 'executable is highly-potentially malicious, add this '
                                             'hash manually to the clean refset if you are sure it\'s OK',
                                             detection_points, enginesstr, hashfile + " | " + product + " | " + description)
            self.sender.send(msg)
        '''    for hsh, pos, tot in bad:
            for ip in hashes[hsh.lower()]:
                msg = Worker.MSG_TEMPLATE % ('bad', ip, hsh, 'malicious executable detected',
                                             pos, tot, hashes[hsh][ip]['value'])
                self.sender.send(msg) '''
        for resphash, haship, hashfile, hashdomain, product, description in unknown:
            msg = Worker.MSG_TEMPLATE % ('unknown', haship, hashdomain, resphash, 'executable is unknown',
                                        '', '', '')
            self.sender.send(msg)

    def vt_tasks(self, session, hashkeys):
        tasks = []
        for qhash in hashkeys[:self.config.max_hashes]:
            url = self.VT_BASE_API+qhash
            headers = {'x-apikey': next(self.iterkeys)}
            tasks.append(session.get(url, headers=headers, ssl=False))
        return tasks

    async def get_vt_results(self, hashkeys):
        async with aiohttp.ClientSession() as session:
            tasks = self.vt_tasks(session, hashkeys)
            responses = await asyncio.gather(*tasks)
            for resp in responses:
                hashdone = str(resp.url).rsplit('/', 1)[-1]
                if resp.status == 200:
    #                respd = {}
    #                last_analysis_results = []
                    respjson = await resp.json()
    #                respd[hashdone] = respjson
                    self.vtresponses[hashdone] = respjson
#                    self.payback_hash_list.append(hashdone)
#                    del self.hashes[hashdone]
                elif resp.status == 404:
                    self.vtresponses[hashdone] = "Not Found"
#                    self.payback_hash_list.append(hashdone)
                else:
                    self.payback_hash_list.append(hashdone)
                    respjson = await resp.json()
                    LOGGER.warning(hashdone+"  "+respjson)
#                    print(str(resp.status)+": "+hashdone)
#                    print(await resp.json())

    def run(self):
        LOGGER.info('Fetching hashes from QRadar')
        loaded_hashes = self.load_hashes()
        if 'number_of_elements' in loaded_hashes and loaded_hashes['number_of_elements'] == 0:
            LOGGER.info('No hashes to process')
            return
        if 'data' not in loaded_hashes:
            LOGGER.warning('No data section with hashes found')
            return

        loaded_hashes = loaded_hashes['data']

        LOGGER.info('Purging hashes fetched')
        self.purge_hashes()

#        hashes = dict()
        for key in loaded_hashes:
            self.hashes[key.lower()] = loaded_hashes[key]

        count = 0
        hash_keys = list(self.hashes.keys())
        LOGGER.debug('Num of keys to check: %s' % str(len(hash_keys)))
#        payback_hash_list = list()
#        clean_hash_list = list()
        execloop = 0

############# Igor S. Custom #########################################################################

        while len(hash_keys) > 0 or self.config.rate_limit <= execloop:
            LOGGER.debug('Querying for hashes: %s' % str(','.join(hash_keys)))
            unknowns = list()
            clean = list()
            low = list()
            high = list()
            bad = list()
            get_vt_loop = asyncio.get_event_loop()
            get_vt_loop.run_until_complete(self.get_vt_results(hash_keys))
            for resphash in self.vtresponses.keys():
                class1mal = []
                class2mal = []
                class3mal = []

                haship = self.hashes[resphash]['SourceIP']['value']
                hashfile = self.hashes[resphash]['FileName']['value']
                hashdomain = self.hashes[resphash]['Domain']['value']

                product = ""
                description = ""
                detection_points = 0

                try:
                    product = self.vtresponses[resphash]["data"]["attributes"]["signature_info"]['product']
                except KeyError:
                    pass

                try:
                    description = self.vtresponses[resphash]["data"]["attributes"]["signature_info"]['description']
                except KeyError:
                    pass

                if self.vtresponses[resphash] == "Not Found":
                    unknowns.append((resphash, haship, hashfile, hashdomain, product, description))
                    continue

                engineres = self.vtresponses[resphash]["data"]["attributes"]["last_analysis_results"]
                maldetections = int(self.vtresponses[resphash]["data"]["attributes"]["last_analysis_stats"]['malicious'])
                if maldetections == 0:
                    clean.append((resphash, haship, hashfile, hashdomain, product, description))
                    self.clean_hash_list.append(resphash)
                    continue

                for engine in engineres.keys():
                    if engineres[engine]['category'] == "malicious":
                        if engine in self.config.vt_enginesc1:
                            class1mal.append(engine)
                            detection_points = detection_points + 3
                        elif engine in self.config.vt_enginesc2:
                            class2mal.append(engine)
                            detection_points = detection_points + 2
                        else:
                            class3mal.append(engine)
                            detection_points = detection_points + 1

                if len(class1mal) >= 2 and detection_points > 10:
                    high.append((resphash, haship, hashfile, hashdomain, str(detection_points), class1mal+class2mal+class3mal, product, description))
                elif len(class1mal) == 1 and len(class2mal) >= 2 and detection_points > 10:
                    high.append((resphash, haship, hashfile, hashdomain, str(detection_points), class1mal+class2mal+class3mal, product, description))
                else:
                    low.append((resphash, haship, hashfile, hashdomain, str(detection_points), class1mal+class2mal+class3mal, product, description))

                hash_keys.remove(resphash)

            self.send_messages(hashes=self.hashes, clean=clean, low=low, high=high, bad=bad, unknown=unknowns)
#            hash_keys = list(self.hashes.keys())
            self.vtresponses = {}
            execloop = execloop + 1

        if self.clean_hash_list:
            self.update_hashes(self.CLEAN_SET_NAME, 'sets', self.clean_hash_list)

        hashback = self.payback_hash_list + hash_keys
        if len(hashback) > 0:
            LOGGER.debug('Payback list: %s' % str(hashback))
            hashes_payback = {}
            for qhash in hashback:
                hashes_payback[qhash] = dict()
                hashes_payback[qhash]['SourceIP'] = self.hashes[qhash]['SourceIP']['value']
                hashes_payback[qhash]['FileName'] = self.hashes[qhash]['FileName']['value']
                hashes_payback[qhash]['Domain'] = self.hashes[qhash]['Domain']['value']
            self.update_hashes('virustotal_to_check_v2C', 'tables', hashes_payback)


######################################################################################################
        ''' 
        start_index = 0
        end_index = self.config.max_hashes
        hash_slice = hash_keys[start_index:end_index]
        self.api_keys[self.current_key_index]['timestamp'] = int(time.time())
        while hash_slice:
            # LOGGER.debug('Hash slice: %s' % str(hash_slice))
            hashes_to_vt = ','.join(hash_slice)
            LOGGER.debug('Querying for hashes: %s' % str(hashes_to_vt))
            params = {
                'apikey': self.api_keys[self.current_key_index]['key'],
                'resource': hashes_to_vt
            }
            LOGGER.debug('Using key: %s' % params['apikey'])
            status, code, reports = self.vt_requester.file_report(params=params)

            unknowns = list()
            clean = list()
            low = list()
            high = list()
            bad = list()
            if status:
                if not isinstance(reports, list):
                    reports = [reports]
                for report in reports:
                    if report['response_code'] != 1:
                        unknowns.append(report['resource'])
                        continue
                    if report['positives'] == 0:
                        clean.append((report['resource'], report['positives'], report['total']))
                    elif report['positives'] / float(report['total']) >= self.BAD_RATIO:
                        bad.append((report['resource'], report['positives'], report['total']))
                    elif report['positives'] / float(report['total']) >= self.HIGH_RATIO:
                        high.append((report['resource'], report['positives'], report['total']))
                    else:
                        low.append((report['resource'], report['positives'], report['total']))
                self.clean_hash_list.extend([c[0] for c in clean])
                self.send_messages(hashes=self.hashes, clean=clean, low=low, high=high, bad=bad, unknown=unknowns)
                if len(reports) < len(hash_slice):
                    LOGGER.warning('Number of reports is less than the number of hashes requested. Check and reduce '
                                   'Max Hashes parameter. Unfetched hashes will be returned to QRadar for later '
                                   'checking.')
                    self.payback_hash_list.extend(hash_slice[len(reports):])
            else:
                if code == 204:
                    LOGGER.warning('Rate limit exceeded message from VirusTotal')
                    payback_hash_list.extend(hash_slice)
                    self.switch_key()
                    count = 0
                    self.api_keys[self.current_key_index]['timestamp'] = int(time.time())
                elif code == 403:
                    LOGGER.warning('Forbidden message from VirusTotal')
                    self.config.mark_key_failed(self.api_keys[self.current_key_index]['key'])
                    if not self.remove_key():
                        payback_hash_list.extend(hash_keys[start_index:])
                        break
                    else:
                        payback_hash_list.extend(hash_slice)
                        self.switch_key()
                        count = 0
                        self.api_keys[self.current_key_index]['timestamp'] = int(time.time())
                else:
                    LOGGER.error('Unknown error from VirusTotal')
                    payback_hash_list.extend(hash_keys[start_index:])
                    break

            start_index += self.config.max_hashes
            end_index += self.config.max_hashes
            count += 1
            hash_slice = hash_keys[start_index:end_index]
            if count >= self.config.rate_limit:
                self.switch_key()
                count = 0
                self.api_keys[self.current_key_index]['timestamp'] = int(time.time())

        if clean_hash_list:
            self.update_hashes(self.CLEAN_SET_NAME, 'sets', clean_hash_list)

        if payback_hash_list:
            self.payback_error_data(hashes=hashes, payback_hash_list=payback_hash_list)
 '''

def check_pid():
    need_start = False
    is_linux = os.name == 'posix'

    def write_pid(pid_name, pid_value):
        pid_file = open(pid_name, "w")
        pid_file.write(str(pid_value))
        pid_file.close()

    def pid_exists(pid):
        if is_linux:
            import errno
            if pid < 0:
                return False
            try:
                os.kill(pid, 0)
            except OSError as e:
                return e.errno == errno.EPERM
            else:
                return True
        else:
            import ctypes
            import ctypes.wintypes
            _STILL_ACTIVE = 259
            PROCESS_QUERY_INFORMATION = 0x1000
            processHandle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
            if processHandle == 0:
                return False
            exit_code = ctypes.wintypes.DWORD()
            is_running = (ctypes.windll.kernel32.GetExitCodeProcess(processHandle, ctypes.byref(exit_code)) == 0)
            ctypes.windll.kernel32.CloseHandle(processHandle)
            return is_running or exit_code.value == _STILL_ACTIVE

    # check if we are running
    pid_new = int(os.getpid())
    if os.path.isfile(PID_FILE):
        pid_file = open(PID_FILE, "rb")
        try:
            pid_old = int(pid_file.readline())
            pid_file.close()
        except:
            LOGGER.info('Invalid pid representation, cleaning up...')
            pid_file.close()
            os.remove(PID_FILE)
            need_start = True
        else:
            if pid_exists(pid_old):
                LOGGER.info('One instance (pid %s) already running, initialization cancelled.' % pid_old)
            else:
                LOGGER.info('Process found dead, initializing...')
                os.remove(PID_FILE)
                need_start = True
    else:
        LOGGER.info('Process not running, initializing...')
        need_start = True
    if need_start:
        write_pid(PID_FILE, pid_new)
    return need_start, pid_new
