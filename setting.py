"""
CNC Server 전체에 쓰일 각종 옵션들을 설정
"""

LIMIT_CONNECTION = 100              # 동시 접속 제한
LIMIT_SEQ_DATA_COUNT = 999          # 분할 데이터 개수 제한 (dos 방지)
                                    # 250MB * LIMIT_SEQ_DATA_COUNT


SERVER_INFO = ('172.22.70.152', 80)     # ([ip], [port])
ENCODING = 'cp949'
SUB_ENCODING = 'utf-8' # ENCODING이 안먹힐 시 사용할 2순위 charset

"""logger setting"""
LOGGER_NAME = 'cnc_logger'
LOG_LEVEL = 'debug'                 # (debug | info | warning | error | critical)
LOG_PATH = './log/{}.txt'
LOG_FORMAT = {
    'fmt' : '[%(asctime)s] %(message)s',
    'datefmt' : '%Y-%m-%d %H:%M:%S'
}
LOG_PRINT_CONSOLE = False           # log를 콘솔로 출력할지. False일 경우 파일로 저장

TMP_FILE_PATH = "./tmp/"
TMP_FILE_EXTENSION = '.seq.{}'

FILE_PATH = "./file/"
SEQ_SIZE = 2.5e+8 # 250MB