import traceback
import sys
sys.path.append('/opt/app-root')

from app.worker import *


if __name__ == '__main__':
    try:
        LOGGER.info(15 * '#' + ' New start request ' + 15 * '#')
        need_start, my_pid = check_pid()
        if not need_start:
            LOGGER.info('Process already running, ending current process with pid %s' % my_pid)
            sys.exit(0)
        else:
            LOGGER.info('Process started with pid %s' % str(my_pid))

        sleep_time = 30
        worker = Worker()
        LOGGER.debug('Worker inited')
        while True:
            worker.run()
            LOGGER.info('Sleeping for %d seconds' % sleep_time)
            time.sleep(sleep_time)
            worker.refresh_config()
    except WorkerInitException as e:
        LOGGER.exception('WorkerInitException:')
    except WorkerQRadarAPIException as e:
        LOGGER.exception('WorkerQRadarAPIException:')
    except Exception:
        LOGGER.error('Exception: %s' % traceback.format_exc())
        sys.exit(1)
