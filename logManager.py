from datetime import datetime


class Logger:
    LOG_PATH = './log/'

    @classmethod
    def _logging(cls, message):
        now = datetime.now()

        with open(cls.LOG_PATH + now.strftime('%Y%m%d.txt'), 'a') as wf:
            wf.write(now.strftime('%H:%M:%S ') + message + '\n')

    @classmethod
    def info(cls, message):
        cls._logging('[*] ' + message)
    
    @classmethod
    def error(cls, message):
        cls._logging('[!] ' + message)