import logging
import datetime
import setting


logger = logging.getLogger(setting.LOGGER_NAME)

logger.setLevel(level=getattr(logging, setting.LOG_LEVEL.upper()))

log_path = setting.LOG_PATH.format(datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d'))
log_format = logging.Formatter(**setting.LOG_FORMAT)
file_handler = logging.FileHandler(log_path)

file_handler.setFormatter(log_format)
logger.addHandler(file_handler)

""" 로그 경로 업데이트 (서버가 켜진 동안 하루가 지날 수 있다.)
def log_path_update():
    if log_path != setting.LOG_PATH.format(datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')):
        log_path = setting.LOG_PATH.format(datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d')) 
"""